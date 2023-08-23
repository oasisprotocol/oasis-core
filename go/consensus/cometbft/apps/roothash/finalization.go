package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *rootHashApplication) tryFinalizeRounds(
	ctx *tmapi.Context,
) error {
	for _, runtimeID := range roothashApi.RuntimesToFinalize(ctx) {
		if err := app.tryFinalizeRound(ctx, runtimeID, false); err != nil {
			ctx.Logger().Error("failed to finalize block",
				"err", err,
			)
			return err
		}
	}

	return nil
}

func (app *rootHashApplication) tryFinalizeRound(
	ctx *tmapi.Context,
	runtimeID common.Namespace,
	timeout bool,
) error {
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	state := roothashState.NewMutableState(ctx.State())

	// Fetch runtime state.
	rtState, err := app.getRuntimeState(ctx, state, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to get runtime state: %w", err)
	}

	// Finalize round.
	if err = app.tryFinalizeRoundInsideTx(ctx, rtState, timeout); err != nil {
		return err
	}

	// Update runtime state.
	if err := state.SetRuntimeState(ctx, rtState); err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	ctx.Commit()

	return nil
}

func (app *rootHashApplication) tryFinalizeRoundInsideTx( //nolint: gocyclo
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	timeout bool,
) error {
	round := rtState.LastBlock.Header.Round + 1
	pool := rtState.CommitmentPool

	// Initialize per-epoch liveness statistics.
	if rtState.LivenessStatistics == nil {
		rtState.LivenessStatistics = roothash.NewLivenessStatistics(len(rtState.Committee.Members))
	}
	livenessStats := rtState.LivenessStatistics

	sc, err := pool.ProcessCommitments(rtState.Committee, rtState.Runtime.Executor.AllowedStragglers, timeout)
	switch err {
	case commitment.ErrDiscrepancyDetected:
		ctx.Logger().Warn("executor discrepancy detected",
			"round", round,
			"priority", rtState.CommitmentPool.HighestRank,
			logging.LogEvent, roothash.LogEventExecutionDiscrepancyDetected,
		)

		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				TypedAttribute(&roothash.ExecutionDiscrepancyDetectedEvent{Rank: rtState.CommitmentPool.HighestRank, Timeout: timeout}).
				TypedAttribute(&roothash.RuntimeIDAttribute{ID: rtState.Runtime.ID}),
		)

		// Re-arm round timeout. Give backup workers enough time to submit commitments.
		prevTimeout := rtState.NextTimeout
		rtState.NextTimeout = ctx.BlockHeight() + 1 + (rtState.Runtime.Executor.RoundTimeout*backupWorkerTimeoutFactorNumerator)/backupWorkerTimeoutFactorDenominator // Current height is ctx.BlockHeight() + 1

		if err = rearmRoundTimeout(ctx, rtState.Runtime.ID, prevTimeout, rtState.NextTimeout); err != nil {
			return err
		}

		// Update the timeout flag to correctly handle the case when the round timeout is set to 0.
		timeout = rtState.NextTimeout == ctx.BlockHeight()+1 // Current height is ctx.BlockHeight() + 1

		// Retry as we may be able to already perform discrepancy resolution.
		sc, err = pool.ProcessCommitments(rtState.Committee, rtState.Runtime.Executor.AllowedStragglers, timeout)
	}

	switch err {
	case nil:
		// The round has been finalized.
	case commitment.ErrStillWaiting:
		// Need more commits.
		ctx.Logger().Debug("insufficient commitments for finality, waiting",
			"round", round,
		)
		return nil
	case commitment.ErrNoSchedulerCommitment, commitment.ErrBadSchedulerCommitment:
		// TODO: Consider slashing the primary scheduler for these offenses.
		fallthrough
	case commitment.ErrInsufficientVotes:
		// Emit empty block and fail the round.
		return app.failRound(ctx, rtState, err)
	case commitment.ErrDiscrepancyDetected:
		// This was already handled above, so it should not happen.
		fallthrough
	default:
		return err
	}

	// The round has been finalized.
	ctx.Logger().Debug("finalized round",
		"round", round,
		"priority", pool.HighestRank,
	)

	livenessStats.TotalRounds++

	// Record if the highest-ranked scheduler received enough commitments.
	firstSchedulerIdx, err := rtState.Committee.SchedulerIdx(round, 0)
	if err != nil {
		return err
	}
	firstScheduler := rtState.Committee.Members[firstSchedulerIdx]

	switch firstScheduler.PublicKey.Equal(sc.Commitment.Header.SchedulerID) {
	case true:
		livenessStats.FinalizedProposals[firstSchedulerIdx]++
	case false:
		livenessStats.MissedProposals[firstSchedulerIdx]++
	}

	state := roothashState.NewMutableState(ctx.State())
	header := sc.Commitment.Header.Header

	// Update the incoming message queue by removing processed messages. Do one final check to
	// make sure that the processed messages actually correspond to the provided hash.
	msgs, err := fetchRuntimeMessages(ctx, state, rtState.Runtime.ID, header.InMessagesCount)
	if err != nil {
		return err
	}
	if err = verifyRuntimeMessages(ctx, msgs, header.InMessagesHash); err != nil {
		// TODO: All nodes contributing to this round should be penalized.
		return app.failRound(ctx, rtState, err)
	}
	if err = app.removeRuntimeMessages(ctx, state, rtState.Runtime.ID, msgs, round); err != nil {
		return err
	}
	msgEvents, err := app.processRuntimeMessages(ctx, rtState, sc.Commitment.Messages)
	if err != nil {
		return fmt.Errorf("failed to process runtime messages: %w", err)
	}

	// Compute good and bad entities.
	var (
		goodComputeEntities []signature.PublicKey
		badComputeEntities  []signature.PublicKey
	)
	seen := make(map[signature.PublicKey]struct{})
	regState := registryState.NewMutableState(ctx.State())
	schedulerVote := sc.Commitment.ToVote()
	for i, n := range rtState.Committee.Members {
		vote, ok := sc.Votes[n.PublicKey]
		// Make sure to not include nodes in multiple roles multiple times.
		_, wasSeen := seen[n.PublicKey]
		seen[n.PublicKey] = struct{}{}
		switch {
		case !ok && n.Role == scheduler.RoleBackupWorker && !pool.Discrepancy && !wasSeen:
			// This is a backup worker only that did not submit a commitment and there was no
			// discrepancy. Count the worker as live.
			//
			// Note that this skips the case where the node is both primary and backup and the
			// primary did not commit as that should be treated as failure.
			livenessStats.LiveRounds[i]++
			continue
		case !ok || vote == nil || wasSeen:
			continue
		default:
		}

		// Resolve the entity owning the node.
		var node *node.Node
		node, err = regState.Node(ctx, n.PublicKey)
		switch err {
		case nil:
		case registry.ErrNoSuchNode:
			// This should never happen as nodes cannot disappear mid-epoch.
			ctx.Logger().Error("runtime node not found by commitment signature public key",
				"public_key", n.PublicKey,
			)
			continue
		default:
			ctx.Logger().Error("failed to get runtime node by commitment signature public key",
				"public_key", n.PublicKey,
				"err", err,
			)
			return fmt.Errorf("cometbft/roothash: getting node %s: %w", n.PublicKey, err)
		}

		// Determine whether the entity was good or bad.
		switch vote.Equal(&schedulerVote) {
		case true:
			goodComputeEntities = append(goodComputeEntities, node.EntityID)
			livenessStats.LiveRounds[i]++
		case false:
			badComputeEntities = append(badComputeEntities, node.EntityID)
		}
	}

	// If there was a discrepancy, slash entities for incorrect results if configured.
	switch rtState.CommitmentPool.Discrepancy {
	case true:
		ctx.Logger().Debug("executor pool discrepancy",
			"slashing", rtState.Runtime.Staking.Slashing,
		)

		penalty, ok := rtState.Runtime.Staking.Slashing[staking.SlashRuntimeIncorrectResults]
		if !ok || penalty.Amount.IsZero() {
			break
		}

		// Slash for incorrect results.
		if err = onRuntimeIncorrectResults(
			ctx,
			badComputeEntities,
			goodComputeEntities,
			rtState.Runtime,
			&penalty.Amount,
		); err != nil {
			return fmt.Errorf("failed to slash for incorrect results: %w", err)
		}
	case false:
		// No slashing needed.
	}

	// Set last normal round results.
	results := roothash.RoundResults{
		Messages:            msgEvents,
		GoodComputeEntities: goodComputeEntities,
		BadComputeEntities:  badComputeEntities,
	}
	if err = state.SetLastRoundResults(ctx, rtState.Runtime.ID, &results); err != nil {
		return fmt.Errorf("failed to set last round results: %w", err)
	}

	// Generate the final block.
	return app.finalizeBlock(ctx, rtState, block.Normal, &sc.Commitment.Header.Header)
}

func (app *rootHashApplication) finalizeBlock(ctx *tmapi.Context, rtState *roothash.RuntimeState, hdrType block.HeaderType, hdr *commitment.ComputeResultsHeader) error {
	// Generate a new block.
	blk := block.NewEmptyBlock(rtState.LastBlock, uint64(ctx.Now().Unix()), hdrType)

	switch hdrType {
	case block.Normal:
		blk.Header.IORoot = *hdr.IORoot
		blk.Header.StateRoot = *hdr.StateRoot
		blk.Header.MessagesHash = *hdr.MessagesHash
		blk.Header.InMessagesHash = *hdr.InMessagesHash
	}

	// Hook up the new block.
	rtState.LastBlock = blk
	rtState.LastBlockHeight = ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1

	switch hdrType {
	case block.Normal:
		rtState.LastNormalRound = blk.Header.Round
		rtState.LastNormalHeight = ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1
	}

	// Emit event.
	ctx.Logger().Debug("new runtime block",
		"height", ctx.BlockHeight()+1, // Current height is ctx.BlockHeight() + 1
		"round", blk.Header.Round,
		"type", blk.Header.HeaderType,
		"time", blk.Header.Timestamp,
	)

	ctx.EmitEvent(
		tmapi.NewEventBuilder(app.Name()).
			TypedAttribute(&roothash.FinalizedEvent{Round: blk.Header.Round}).
			TypedAttribute(&roothash.RuntimeIDAttribute{ID: rtState.Runtime.ID}),
	)

	// Reset scheduler commitments.
	switch hdrType {
	case block.Suspended:
		rtState.CommitmentPool = nil
	default:
		rtState.CommitmentPool = commitment.NewPool()
	}

	// Re-arm round timeout. Give schedulers unlimited time to submit commitments.
	prevTimeout := rtState.NextTimeout
	rtState.NextTimeout = roothash.TimeoutNever

	return rearmRoundTimeout(ctx, rtState.Runtime.ID, prevTimeout, rtState.NextTimeout)
}

func (app *rootHashApplication) failRound(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	err error,
) error {
	round := rtState.LastBlock.Header.Round + 1

	ctx.Logger().Debug("round failed",
		"round", round,
		"err", err,
		logging.LogEvent, roothash.LogEventRoundFailed,
	)

	// Record that the scheduler did not receive enough commitments.
	schedulerIdx, err := rtState.Committee.SchedulerIdx(round, 0)
	if err != nil {
		// No workers in the committee.
		return err
	}

	rtState.LivenessStatistics.MissedProposals[schedulerIdx]++

	if err := app.finalizeBlock(ctx, rtState, block.RoundFailed, nil); err != nil {
		return fmt.Errorf("failed to emit empty block: %w", err)
	}

	return nil
}
