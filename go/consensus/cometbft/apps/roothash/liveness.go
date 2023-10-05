package roothash

import (
	"fmt"
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// processLivenessStatistics checks the liveness statistics for the last epoch and penalizes any
// nodes that didn't satisfy the liveness condition.
func processLivenessStatistics(ctx *tmapi.Context, epoch beacon.EpochTime, rtState *roothash.RuntimeState) error {
	if rtState.Committee == nil || rtState.CommitmentPool == nil || rtState.LivenessStatistics == nil || rtState.Suspended {
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

	// Penalize worker nodes that were not live enough.
	regState := registryState.NewMutableState(ctx.State())
	for i, n := range rtState.Committee.Members {
		if n.Role != api.RoleWorker {
			// Workers are listed before backup workers.
			break
		}

		status, err := regState.NodeStatus(ctx, n.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to retrieve status for node %s: %w", n.PublicKey, err)
		}
		if status.IsSuspended(rtState.Runtime.ID, epoch) {
			continue
		}

		liveRounds := rtState.LivenessStatistics.LiveRounds[i]
		finalizedProposals := rtState.LivenessStatistics.FinalizedProposals[i]
		missedProposals := rtState.LivenessStatistics.MissedProposals[i]

		maxMissedProposals := ((missedProposals + finalizedProposals) * maxMissedProposalsPercent) / 100
		if maxMissedProposalsPercent == 0 {
			maxMissedProposals = math.MaxUint64
		}

		switch {
		case liveRounds >= minLiveRounds && missedProposals <= maxMissedProposals:
			// Node is live.
			status.RecordSuccess(rtState.Runtime.ID, epoch)
		default:
			// Node is faulty.
			ctx.Logger().Debug("node deemed faulty",
				"node_id", n.PublicKey,
				"live_rounds", liveRounds,
				"min_live_rounds", minLiveRounds,
				"missed_proposals", missedProposals,
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
				err = onRuntimeLivenessFailure(ctx, n.PublicKey, &slashParams.Amount)
				if err != nil {
					return fmt.Errorf("failed to slash node %s: %w", n.PublicKey, err)
				}
			}
		}

		if err = regState.SetNodeStatus(ctx, n.PublicKey, status); err != nil {
			return fmt.Errorf("failed to set node status for node %s: %w", n.PublicKey, err)
		}
	}

	return nil
}
