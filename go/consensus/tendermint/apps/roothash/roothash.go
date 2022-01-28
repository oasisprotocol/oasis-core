// Package roothash implements the roothash application.
package roothash

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ tmapi.Application = (*rootHashApplication)(nil)

type rootHashApplication struct {
	state tmapi.ApplicationState
	md    tmapi.MessageDispatcher
}

func (app *rootHashApplication) Name() string {
	return AppName
}

func (app *rootHashApplication) ID() uint8 {
	return AppID
}

func (app *rootHashApplication) Methods() []transaction.MethodName {
	return roothash.Methods
}

func (app *rootHashApplication) Blessed() bool {
	return false
}

func (app *rootHashApplication) Dependencies() []string {
	return []string{schedulerapp.AppName, stakingapp.AppName}
}

func (app *rootHashApplication) OnRegister(state tmapi.ApplicationState, md tmapi.MessageDispatcher) {
	app.state = state
	app.md = md

	// Subscribe to messages emitted by other apps.
	md.Subscribe(registryApi.MessageNewRuntimeRegistered, app)
	md.Subscribe(registryApi.MessageRuntimeUpdated, app)
	md.Subscribe(registryApi.MessageRuntimeResumed, app)
	md.Subscribe(roothashApi.RuntimeMessageNoop, app)
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) BeginBlock(ctx *tmapi.Context, request types.RequestBeginBlock) error {
	// Check if rescheduling has taken place.
	rescheduled := ctx.HasEvent(schedulerapp.AppName, schedulerapp.KeyElected)
	// Check if there was an epoch transition.
	epochChanged, epoch := app.state.EpochChanged(ctx)

	state := roothashState.NewMutableState(ctx.State())

	switch {
	case epochChanged, rescheduled:
		return app.onCommitteeChanged(ctx, state, epoch)
	}

	return nil
}

func (app *rootHashApplication) onCommitteeChanged(ctx *tmapi.Context, state *roothashState.MutableState, epoch beacon.EpochTime) error {
	schedState := schedulerState.NewMutableState(ctx.State())
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes(ctx)

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}

	var stakeAcc *stakingState.StakeAccumulatorCache
	if !params.DebugBypassStake {
		stakeAcc, err = stakingState.NewStakeAccumulatorCache(ctx)
		if err != nil {
			return fmt.Errorf("failed to create stake accumulator cache: %w", err)
		}
		defer stakeAcc.Discard()
	}

	for _, rt := range runtimes {
		if !rt.IsCompute() {
			ctx.Logger().Debug("skipping non-compute runtime",
				"runtime", rt.ID,
			)
			continue
		}

		rtState, err := state.RuntimeState(ctx, rt.ID)
		if err != nil {
			return fmt.Errorf("failed to fetch runtime state: %w", err)
		}

		// Expire past evidence of runtime node misbehaviour.
		if rtState.CurrentBlock != nil {
			if round := rtState.CurrentBlock.Header.Round; round > params.MaxEvidenceAge {
				ctx.Logger().Debug("removing expired runtime evidence",
					"runtime", rt.ID,
					"round", round,
					"max_evidence_age", params.MaxEvidenceAge,
				)
				if err = state.RemoveExpiredEvidence(ctx, rt.ID, round-params.MaxEvidenceAge); err != nil {
					return fmt.Errorf("failed to remove expired runtime evidence: %s %w", rt.ID, err)
				}
			}
		}

		// Since the runtime is in the list of active runtimes in the registry we
		// can safely clear the suspended flag.
		rtState.Suspended = false

		// Prepare new runtime committees based on what the scheduler did.
		executorPool, empty, err := app.prepareNewCommittees(ctx, epoch, rtState, schedState, regState)
		if err != nil {
			return err
		}

		// If there are no committees for this runtime, suspend the runtime as this
		// means that there is noone to pay the maintenance fees.
		//
		// Also suspend the runtime in case the registering entity no longer has enough stake to
		// cover the entity and runtime deposits (this check is skipped if the runtime would be
		// suspended anyway due to nobody being there to pay maintenance fees).
		sufficientStake := true
		if !empty && !params.DebugBypassStake && rt.GovernanceModel != registry.GovernanceConsensus {
			acctAddr := rt.StakingAddress()
			if acctAddr == nil {
				// This should never happen.
				ctx.Logger().Error("unknown runtime governance model",
					"rt_id", rt.ID,
					"gov_model", rt.GovernanceModel,
				)
				return fmt.Errorf("unknown runtime governance model on runtime %s: %s", rt.ID, rt.GovernanceModel)
			}

			if err = stakeAcc.CheckStakeClaims(*acctAddr); err != nil {
				ctx.Logger().Warn("insufficient stake for runtime operation",
					"err", err,
					"entity", rt.EntityID,
					"account", *acctAddr,
				)
				sufficientStake = false
			}
		}
		if (empty || !sufficientStake) && !params.DebugDoNotSuspendRuntimes {
			if err = app.suspendUnpaidRuntime(ctx, rtState, regState); err != nil {
				return err
			}
		}

		// If the committee has actually changed, force a new round.
		if !rtState.Suspended {
			ctx.Logger().Debug("updating committee for runtime",
				"runtime_id", rt.ID,
			)

			// Transition the round.
			ctx.Logger().Debug("new committee, transitioning round",
				"runtime_id", rt.ID,
				"round", rtState.CurrentBlock.Header.Round,
			)

			// Emit an empty epoch transition block in the new round. This is required so that
			// the clients can be sure what state is final when an epoch transition occurs.
			if err = app.emitEmptyBlock(ctx, rtState, block.EpochTransition); err != nil {
				return fmt.Errorf("failed to emit empty block: %w", err)
			}

			// Set the executor pool.
			rtState.ExecutorPool = executorPool
			rtState.ExecutorPool.Round = rtState.CurrentBlock.Header.Round
		}

		// Update the runtime descriptor to the latest per-epoch value.
		rtState.Runtime = rt

		if err = state.SetRuntimeState(ctx, rtState); err != nil {
			return fmt.Errorf("failed to set runtime state: %w", err)
		}
	}

	return nil
}

func (app *rootHashApplication) suspendUnpaidRuntime(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	regState *registryState.MutableState,
) error {
	ctx.Logger().Warn("maintenance fees not paid for runtime or owner debonded, suspending",
		"runtime_id", rtState.Runtime.ID,
	)

	if err := regState.SuspendRuntime(ctx, rtState.Runtime.ID); err != nil {
		return err
	}

	// Emity an empty block signalling that the runtime was suspended.
	if err := app.emitEmptyBlock(ctx, rtState, block.Suspended); err != nil {
		return fmt.Errorf("failed to emit empty block: %w", err)
	}

	// Make sure to only reset the executor pool after any timeouts have been cleared as otherwise
	// the emitEmptyBlock method will forget to clear them.
	rtState.Suspended = true
	rtState.ExecutorPool = nil

	return nil
}

func (app *rootHashApplication) prepareNewCommittees(
	ctx *tmapi.Context,
	epoch beacon.EpochTime,
	rtState *roothash.RuntimeState,
	schedState *schedulerState.MutableState,
	regState *registryState.MutableState,
) (
	executorPool *commitment.Pool,
	empty bool,
	err error,
) {
	rtID := rtState.Runtime.ID

	executorPool = new(commitment.Pool)
	executorCommittee, err := schedState.Committee(ctx, scheduler.KindComputeExecutor, rtID)
	if err != nil {
		ctx.Logger().Error("checkCommittees: failed to get executor committee from scheduler",
			"err", err,
			"runtime", rtID,
		)
		return
	}
	if executorCommittee == nil {
		ctx.Logger().Warn("checkCommittees: no executor committee",
			"runtime", rtID,
		)
		empty = true
	} else {
		executorPool = &commitment.Pool{
			Runtime:   rtState.Runtime,
			Committee: executorCommittee,
		}
	}
	return
}

func (app *rootHashApplication) emitEmptyBlock(ctx *tmapi.Context, runtime *roothash.RuntimeState, hdrType block.HeaderType) error {
	blk := block.NewEmptyBlock(runtime.CurrentBlock, uint64(ctx.Now().Unix()), hdrType)

	runtime.CurrentBlock = blk
	runtime.CurrentBlockHeight = ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1
	// Do not update LastNormal{Round,Height} as empty blocks are not emitted by the runtime.
	if runtime.ExecutorPool != nil {
		// Clear timeout if there was one scheduled.
		if runtime.ExecutorPool.NextTimeout != commitment.TimeoutNever {
			state := roothashState.NewMutableState(ctx.State())
			if err := state.ClearRoundTimeout(ctx, runtime.Runtime.ID, runtime.ExecutorPool.NextTimeout); err != nil {
				return fmt.Errorf("failed to clear round timeout: %w", err)
			}
		}
		runtime.ExecutorPool.ResetCommitments(blk.Header.Round)
	}

	tagV := ValueFinalized{
		ID: runtime.Runtime.ID,
		Event: roothash.FinalizedEvent{
			Round: blk.Header.Round,
		},
	}
	ctx.EmitEvent(
		tmapi.NewEventBuilder(app.Name()).
			Attribute(KeyFinalized, cbor.Marshal(tagV)).
			Attribute(KeyRuntimeID, ValueRuntimeID(runtime.Runtime.ID)),
	)
	return nil
}

func (app *rootHashApplication) ExecuteMessage(ctx *tmapi.Context, kind, msg interface{}) error {
	switch kind {
	case registryApi.MessageNewRuntimeRegistered:
		// A new runtime has been registered.
		if ctx.IsInitChain() {
			// Ignore messages emitted during InitChain as we handle these separately.
			return nil
		}
		rt := msg.(*registry.Runtime)

		ctx.Logger().Debug("ExecuteMessage: new runtime",
			"runtime", rt.ID,
		)

		return app.onNewRuntime(ctx, rt, nil, false)
	case registryApi.MessageRuntimeUpdated:
		// A runtime registration has been updated or a new runtime has been registered.
		if ctx.IsInitChain() {
			// Ignore messages emitted during InitChain as we handle these separately.
			return nil
		}
		return app.verifyRuntimeUpdate(ctx, msg.(*registry.Runtime))
	case registryApi.MessageRuntimeResumed:
		// A previously suspended runtime has been resumed.
		return nil
	case roothashApi.RuntimeMessageNoop:
		// Noop message always succeeds.
		return nil
	default:
		return roothash.ErrInvalidArgument
	}
}

func (app *rootHashApplication) verifyRuntimeUpdate(ctx *tmapi.Context, rt *registry.Runtime) error {
	state := roothashState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}

	return roothash.VerifyRuntimeParameters(ctx.Logger(), rt, params)
}

func (app *rootHashApplication) ExecuteTx(ctx *tmapi.Context, tx *transaction.Transaction) error {
	state := roothashState.NewMutableState(ctx.State())

	switch tx.Method {
	case roothash.MethodExecutorCommit:
		var xc roothash.ExecutorCommit
		if err := cbor.Unmarshal(tx.Body, &xc); err != nil {
			return err
		}

		return app.executorCommit(ctx, state, &xc)
	case roothash.MethodExecutorProposerTimeout:
		var xc roothash.ExecutorProposerTimeoutRequest
		if err := cbor.Unmarshal(tx.Body, &xc); err != nil {
			return err
		}

		return app.executorProposerTimeout(ctx, state, &xc)
	case roothash.MethodEvidence:
		var ev roothash.Evidence
		if err := cbor.Unmarshal(tx.Body, &ev); err != nil {
			return err
		}

		return app.submitEvidence(ctx, state, &ev)
	case roothash.MethodSubmitMsg:
		var msg roothash.SubmitMsg
		if err := cbor.Unmarshal(tx.Body, &msg); err != nil {
			return err
		}

		return app.submitMsg(ctx, state, &msg)
	default:
		return roothash.ErrInvalidArgument
	}
}

func (app *rootHashApplication) onNewRuntime(ctx *tmapi.Context, runtime *registry.Runtime, genesis *roothash.Genesis, suspended bool) error {
	if !runtime.IsCompute() {
		ctx.Logger().Warn("onNewRuntime: ignoring non-compute runtime",
			"runtime", runtime,
		)
		return nil
	}

	// Check if state already exists for the given runtime.
	state := roothashState.NewMutableState(ctx.State())
	_, err := state.RuntimeState(ctx, runtime.ID)
	switch err {
	case nil:
		ctx.Logger().Warn("onNewRuntime: state for runtime already exists",
			"runtime", runtime,
		)
		return nil
	case roothash.ErrInvalidRuntime:
		// Runtime does not yet exist.
	default:
		return fmt.Errorf("failed to fetch runtime state: %w", err)
	}

	// Create genesis block.
	now := ctx.Now().Unix()
	genesisBlock := block.NewGenesisBlock(runtime.ID, uint64(now))
	// Fill the Header fields with Genesis runtime states, if this was called during InitChain().
	genesisBlock.Header.Round = runtime.Genesis.Round
	genesisBlock.Header.StateRoot = runtime.Genesis.StateRoot
	if ctx.IsInitChain() {
		// NOTE: Outside InitChain the genesis argument will be nil.
		if genesisRts := genesis.RuntimeStates[runtime.ID]; genesisRts != nil {
			genesisBlock.Header.Round = genesisRts.Round
			genesisBlock.Header.StateRoot = genesisRts.StateRoot
			if suspended {
				genesisBlock.Header.HeaderType = block.Suspended
			}

			err = state.SetLastRoundResults(ctx, runtime.ID, &roothash.RoundResults{
				Messages: genesisRts.MessageResults,
			})
			if err != nil {
				return fmt.Errorf("failed to set last round results: %w", err)
			}
		}
	}

	// Create new state containing the genesis block.
	err = state.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            runtime,
		CurrentBlock:       genesisBlock,
		CurrentBlockHeight: ctx.BlockHeight() + 1, // Current height is ctx.BlockHeight() + 1
		LastNormalRound:    genesisBlock.Header.Round,
		LastNormalHeight:   ctx.BlockHeight() + 1, // Current height is ctx.BlockHeight() + 1
		GenesisBlock:       genesisBlock,
	})
	if err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	ctx.Logger().Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	// This transaction now also includes a new block for the given runtime.
	tagV := ValueFinalized{
		ID: runtime.ID,
		Event: roothash.FinalizedEvent{
			Round: genesisBlock.Header.Round,
		},
	}
	ctx.EmitEvent(
		tmapi.NewEventBuilder(app.Name()).
			Attribute(KeyFinalized, cbor.Marshal(tagV)).
			Attribute(KeyRuntimeID, ValueRuntimeID(runtime.ID)),
	)
	return nil
}

func (app *rootHashApplication) EndBlock(ctx *tmapi.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	state := roothashState.NewMutableState(ctx.State())

	// Check if any runtimes require round timeouts to expire.
	roundTimeouts, err := state.RuntimesWithRoundTimeouts(ctx, ctx.BlockHeight())
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("failed to fetch runtimes with round timeouts: %w", err)
	}
	for _, runtimeID := range roundTimeouts {
		if err = app.processRoundTimeout(ctx, state, runtimeID); err != nil {
			return types.ResponseEndBlock{}, fmt.Errorf("failed to process round timeout: %w", err)
		}
	}

	return types.ResponseEndBlock{}, nil
}

func (app *rootHashApplication) processRoundTimeout(ctx *tmapi.Context, state *roothashState.MutableState, runtimeID common.Namespace) error {
	ctx.Logger().Warn("round timeout expired, forcing finalization",
		logging.LogEvent, roothash.LogEventTimerFired,
	)

	rtState, err := state.RuntimeState(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to get runtime state: %w", err)
	}

	if rtState.ExecutorPool == nil {
		// This should NEVER happen as the timeout should be cleared before the pool is reset.
		ctx.Logger().Error("no executor pool",
			"runtime_id", runtimeID,
		)
		return fmt.Errorf("no executor pool")
	}

	if !rtState.ExecutorPool.IsTimeout(ctx.BlockHeight()) {
		// This should NEVER happen.
		ctx.Logger().Error("no scheduled timeout",
			"runtime_id", runtimeID,
			"height", ctx.BlockHeight(),
			"next_timeout", rtState.ExecutorPool.NextTimeout,
		)
		return fmt.Errorf("no scheduled timeout")
	}

	if err = app.tryFinalizeBlock(ctx, rtState, true); err != nil {
		ctx.Logger().Error("failed to finalize block",
			"err", err,
		)
		return fmt.Errorf("failed to finalize block: %w", err)
	}

	return nil
}

// tryFinalizeExecutorCommits tries to finalize the executor commitments into a new runtime block.
// The caller must take care of clearing and scheduling the round timeouts.
func (app *rootHashApplication) tryFinalizeExecutorCommits(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	forced bool,
) error {
	runtime := rtState.Runtime
	round := rtState.CurrentBlock.Header.Round + 1
	pool := rtState.ExecutorPool

	commit, err := pool.TryFinalize(ctx.BlockHeight(), runtime.Executor.RoundTimeout, forced, true)
	if err == commitment.ErrDiscrepancyDetected {
		ctx.Logger().Warn("executor discrepancy detected",
			"round", round,
			logging.LogEvent, roothash.LogEventExecutionDiscrepancyDetected,
		)

		tagV := ValueExecutionDiscrepancyDetected{
			ID: runtime.ID,
			Event: roothash.ExecutionDiscrepancyDetectedEvent{
				Timeout: forced,
			},
		}
		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				Attribute(KeyExecutionDiscrepancyDetected, cbor.Marshal(tagV)).
				Attribute(KeyRuntimeID, ValueRuntimeID(runtime.ID)),
		)

		// We may also be able to already perform discrepancy resolution, check if this is possible
		// by retrying finalization. We must make sure to not affect the computed timeout.
		nextTimeout := pool.NextTimeout
		commit, err = pool.TryFinalize(ctx.BlockHeight(), runtime.Executor.RoundTimeout, false, false)
		pool.NextTimeout = nextTimeout
	}

	switch err {
	case nil:
		// Round has been finalized.
		ctx.Logger().Debug("finalized round",
			"round", round,
		)

		ec := commit.ToDDResult().(*commitment.ExecutorCommitment)

		// Update the incoming message queue by removing processed messages. Do one final check to
		// make sure that the processed messages actually correspond to the provided hash.
		state := roothashState.NewMutableState(ctx.State())
		if ec.Header.InMessagesCount > 0 {
			var meta *message.IncomingMessageQueueMeta
			meta, err = state.IncomingMessageQueueMeta(ctx, rtState.Runtime.ID)
			if err != nil {
				return fmt.Errorf("failed to fetch incoming message queue metadata: %w", err)
			}
			var msgs []*message.IncomingMessage
			msgs, err = state.IncomingMessageQueue(ctx, rtState.Runtime.ID, 0, ec.Header.InMessagesCount)
			if err != nil {
				return fmt.Errorf("failed to fetch incoming message queue: %w", err)
			}
			if inMsgsHash := message.InMessagesHash(msgs); !ec.Header.InMessagesHash.Equal(&inMsgsHash) {
				ctx.Logger().Debug("finalized round contained invalid incoming message hash, failing instead",
					"in_msgs_hash", inMsgsHash,
					"ec_in_msgs_hash", *ec.Header.InMessagesHash,
				)
				// Make the round fail.
				err = fmt.Errorf("finalized round contained invalid incoming message hash")
				// TODO: All nodes contributing to this round should be penalized.
				break
			}
			for _, msg := range msgs {
				err = state.RemoveIncomingMessageFromQueue(ctx, rtState.Runtime.ID, msg.ID)
				if err != nil {
					return fmt.Errorf("failed to remove processed incoming message from queue: %w", err)
				}

				if meta.Size == 0 {
					// This should NEVER happen.
					return tmapi.UnavailableStateError(fmt.Errorf("inconsistent queue size (state corruption?)"))
				}
				meta.Size--

				ctx.EmitEvent(
					tmapi.NewEventBuilder(app.Name()).
						TypedAttribute(&roothash.InMsgProcessedEvent{
							ID:     msg.ID,
							Round:  round,
							Caller: msg.Caller,
							Tag:    msg.Tag,
						}).
						Attribute(KeyRuntimeID, ValueRuntimeID(rtState.Runtime.ID)),
				)
			}
			err = state.SetIncomingMessageQueueMeta(ctx, rtState.Runtime.ID, meta)
			if err != nil {
				return fmt.Errorf("failed to set incoming message queue metadata: %w", err)
			}
		}

		// Process any runtime messages.
		var messageResults []*roothash.MessageEvent
		if messageResults, err = app.processRuntimeMessages(ctx, rtState, ec.Messages); err != nil {
			return fmt.Errorf("failed to process runtime messages: %w", err)
		}

		var (
			goodComputeEntities []signature.PublicKey
			badComputeEntities  []signature.PublicKey
		)
		commitments := pool.ExecuteCommitments
		seen := make(map[signature.PublicKey]bool)
		regState := registryState.NewMutableState(ctx.State())
		for _, n := range pool.Committee.Members {
			c, ok := commitments[n.PublicKey]
			if !ok || c.IsIndicatingFailure() || seen[n.PublicKey] {
				continue
			}
			// Make sure to not include nodes in multiple roles multiple times.
			seen[n.PublicKey] = true

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
				return fmt.Errorf("tendermint/roothash: getting node %s: %w", n.PublicKey, err)
			}

			switch commit.MostlyEqual(c) {
			case true:
				// Correct commit.
				goodComputeEntities = append(goodComputeEntities, node.EntityID)
			case false:
				// Incorrect commit.
				badComputeEntities = append(badComputeEntities, node.EntityID)
			}
		}

		// If there was a discrepancy, slash entities for incorrect results if configured.
		if pool.Discrepancy {
			ctx.Logger().Debug("executor pool discrepancy",
				"slashing", runtime.Staking.Slashing,
			)
			if penalty, ok := rtState.Runtime.Staking.Slashing[staking.SlashRuntimeIncorrectResults]; ok && !penalty.Amount.IsZero() {
				// Slash for incorrect results.
				if err = onRuntimeIncorrectResults(
					ctx,
					badComputeEntities,
					goodComputeEntities,
					runtime,
					&penalty.Amount,
				); err != nil {
					return fmt.Errorf("failed to slash for incorrect results: %w", err)
				}
			}
		}

		// Generate the final block.
		blk := block.NewEmptyBlock(rtState.CurrentBlock, uint64(ctx.Now().Unix()), block.Normal)
		blk.Header.IORoot = *ec.Header.IORoot
		blk.Header.StateRoot = *ec.Header.StateRoot
		blk.Header.MessagesHash = *ec.Header.MessagesHash
		blk.Header.InMessagesHash = *ec.Header.InMessagesHash

		// Timeout will be cleared by caller.
		pool.ResetCommitments(blk.Header.Round)

		// All good. Hook up the new block.
		rtState.CurrentBlock = blk
		rtState.CurrentBlockHeight = ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1
		rtState.LastNormalRound = blk.Header.Round
		rtState.LastNormalHeight = ctx.BlockHeight() + 1

		// Set last normal round results.
		err = state.SetLastRoundResults(ctx, rtState.Runtime.ID, &roothash.RoundResults{
			Messages:            messageResults,
			GoodComputeEntities: goodComputeEntities,
			BadComputeEntities:  badComputeEntities,
		})
		if err != nil {
			return fmt.Errorf("failed to set last round results: %w", err)
		}

		tagV := ValueFinalized{
			ID: rtState.Runtime.ID,
			Event: roothash.FinalizedEvent{
				Round: blk.Header.Round,
			},
		}
		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				Attribute(KeyFinalized, cbor.Marshal(tagV)).
				Attribute(KeyRuntimeID, ValueRuntimeID(rtState.Runtime.ID)),
		)

		return nil
	case commitment.ErrStillWaiting:
		// Need more commits.
		ctx.Logger().Debug("insufficient commitments for finality, waiting",
			"round", round,
		)

		return nil
	case commitment.ErrDiscrepancyDetected:
		// This was already handled above, so it should not happen.
		return nil
	default:
	}

	// Something else went wrong, emit empty error block.
	ctx.Logger().Error("round failed",
		"round", round,
		"err", err,
		logging.LogEvent, roothash.LogEventRoundFailed,
	)

	if err := app.emitEmptyBlock(ctx, rtState, block.RoundFailed); err != nil {
		return fmt.Errorf("failed to emit empty block: %w", err)
	}

	return nil
}

func (app *rootHashApplication) tryFinalizeBlock(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	forced bool,
) error {
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	state := roothashState.NewMutableState(ctx.State())
	previousTimeout := rtState.ExecutorPool.NextTimeout

	if err := app.tryFinalizeExecutorCommits(ctx, rtState, forced); err != nil {
		return err
	}

	// Do not re-arm the round timeout if the timeout has not changed.
	if nextTimeout := rtState.ExecutorPool.NextTimeout; previousTimeout != nextTimeout {
		if previousTimeout != commitment.TimeoutNever {
			if err := state.ClearRoundTimeout(ctx, rtState.Runtime.ID, previousTimeout); err != nil {
				return fmt.Errorf("failed to clear round timeout: %w", err)
			}
		}

		switch nextTimeout {
		case commitment.TimeoutNever:
			// Only clear round timeout (already done).
			ctx.Logger().Debug("disarming round timeout")
		default:
			// Set a different round timeout.
			ctx.Logger().Debug("(re-)arming round timeout",
				"height", ctx.BlockHeight(),
				"next_timeout", nextTimeout,
			)
			if err := state.ScheduleRoundTimeout(ctx, rtState.Runtime.ID, nextTimeout); err != nil {
				return fmt.Errorf("failed to schedule round timeout: %w", err)
			}
		}
	}

	// Update runtime state.
	if err := state.SetRuntimeState(ctx, rtState); err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	ctx.Commit()

	return nil
}

// New constructs a new roothash application instance.
func New() tmapi.Application {
	return &rootHashApplication{}
}
