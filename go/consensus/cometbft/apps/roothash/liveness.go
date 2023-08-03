package roothash

import (
	"fmt"
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// processLivenessStatistics checks the liveness statistics for the last epoch and penalizes any
// nodes that didn't satisfy the liveness condition.
func processLivenessStatistics(ctx *tmapi.Context, epoch beacon.EpochTime, rtState *roothash.RuntimeState) error {
	if rtState.ExecutorPool == nil || rtState.LivenessStatistics == nil || rtState.Suspended {
		return nil
	}

	// Skip evaluation if the number of total live rounds is below the set minimum.
	totalRounds := rtState.LivenessStatistics.TotalRounds
	if totalRounds == 0 || totalRounds < rtState.Runtime.Executor.MinLiveRoundsForEvaluation {
		return nil
	}

	minLiveRoundsPercent := uint64(rtState.Runtime.Executor.MinLiveRoundsPercent)
	minLiveRounds := (rtState.LivenessStatistics.TotalRounds * minLiveRoundsPercent) / 100
	maxFailures := rtState.Runtime.Executor.MaxLivenessFailures
	if maxFailures == 0 {
		maxFailures = 255
	}
	maxMissedProposalsPercent := uint64(rtState.Runtime.Executor.MaxMissedProposalsPercent)
	slashParams := rtState.Runtime.Staking.Slashing[staking.SlashRuntimeLiveness]

	ctx.Logger().Debug("evaluating node liveness",
		"min_live_rounds", minLiveRounds,
		"max_failures", maxFailures,
		"freeze_duration", slashParams.FreezeInterval,
		"slash_amount", slashParams.Amount,
	)

	// Collect per node liveness statistics as a single node can have multiple roles.
	type Stats struct {
		liveRounds         uint64
		finalizedProposals uint64
		missedProposals    uint64
	}
	statsPerNode := make(map[signature.PublicKey]*Stats)
	for i, member := range rtState.ExecutorPool.Committee.Members {
		stats, ok := statsPerNode[member.PublicKey]
		if !ok {
			stats = &Stats{}
			statsPerNode[member.PublicKey] = stats
		}
		stats.liveRounds += rtState.LivenessStatistics.LiveRounds[i]
		stats.finalizedProposals += rtState.LivenessStatistics.FinalizedProposals[i]
		stats.missedProposals += rtState.LivenessStatistics.MissedProposals[i]
	}

	// Penalize nodes that were not live enough.
	regState := registryState.NewMutableState(ctx.State())
	for nodeID, stats := range statsPerNode {
		status, err := regState.NodeStatus(ctx, nodeID)
		if err != nil {
			return fmt.Errorf("failed to retrieve status for node %s: %w", nodeID, err)
		}
		if status.IsSuspended(rtState.Runtime.ID, epoch) {
			continue
		}

		maxMissedProposals := ((stats.missedProposals + stats.finalizedProposals) * maxMissedProposalsPercent) / 100
		if maxMissedProposalsPercent == 0 {
			maxMissedProposals = math.MaxUint64
		}

		switch {
		case stats.liveRounds >= minLiveRounds && stats.missedProposals <= maxMissedProposals:
			// Node is live.
			status.RecordSuccess(rtState.Runtime.ID, epoch)
		default:
			// Node is faulty.
			ctx.Logger().Debug("node deemed faulty",
				"node_id", nodeID,
				"live_rounds", stats.liveRounds,
				"min_live_rounds", minLiveRounds,
				"missed_proposals", stats.missedProposals,
				"max_missed_proposals", maxMissedProposals,
			)

			status.RecordFailure(rtState.Runtime.ID, epoch)

			// Check if the node has reached the maximum allowed number of failures.
			fault := status.Faults[rtState.Runtime.ID]
			if fault.Failures >= maxFailures {
				// Make sure to freeze forever if this would otherwise overflow.
				if epoch > registry.FreezeForever-slashParams.FreezeInterval {
					status.FreezeEndTime = registry.FreezeForever
				} else {
					status.FreezeEndTime = epoch + slashParams.FreezeInterval
				}

				// Slash if configured.
				err = onRuntimeLivenessFailure(ctx, nodeID, &slashParams.Amount)
				if err != nil {
					return fmt.Errorf("failed to slash node %s: %w", nodeID, err)
				}
			}
		}

		if err = regState.SetNodeStatus(ctx, nodeID, status); err != nil {
			return fmt.Errorf("failed to set node status for node %s: %w", nodeID, err)
		}
	}

	return nil
}
