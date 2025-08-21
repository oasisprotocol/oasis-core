// Package roothash implements the roothash application.
package roothash

import (
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/api"
	registryApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	schedulerapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	schedulerApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/api"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Application is a roothash application.
type Application struct {
	state api.ApplicationState
	md    api.MessageDispatcher
	ecn   api.ExecutorCommitmentNotifier
}

// New constructs a new roothash application.
func New(state api.ApplicationState, md api.MessageDispatcher, ecn api.ExecutorCommitmentNotifier) *Application {
	return &Application{
		state: state,
		md:    md,
		ecn:   ecn,
	}
}

// Name implements api.Application.
func (app *Application) Name() string {
	return AppName
}

// ID implements api.Application.
func (app *Application) ID() uint8 {
	return AppID
}

// Methods implements api.Application.
func (app *Application) Methods() []transaction.MethodName {
	return roothash.Methods
}

// Blessed implements api.Application.
func (app *Application) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *Application) Dependencies() []string {
	return []string{schedulerapp.AppName, stakingapp.AppName}
}

// Subscribe implements api.Application.
func (app *Application) Subscribe() {
	// Subscribe to messages emitted by other apps.
	app.md.Subscribe(registryApi.MessageNewRuntimeRegistered, app)
	app.md.Subscribe(registryApi.MessageRuntimeUpdated, app)
	app.md.Subscribe(registryApi.MessageRuntimeResumed, app)
	app.md.Subscribe(roothashApi.RuntimeMessageNoop, app)
	app.md.Subscribe(schedulerApi.MessageBeforeSchedule, app)
	app.md.Subscribe(governanceApi.MessageChangeParameters, app)
	app.md.Subscribe(governanceApi.MessageValidateParameterChanges, app)
}

// OnCleanup implements api.Application.
func (app *Application) OnCleanup() {
}

// BeginBlock implements api.Application.
func (app *Application) BeginBlock(ctx *api.Context) error {
	// Check if rescheduling has taken place.
	rescheduled := ctx.HasEvent(schedulerapp.AppName, &scheduler.ElectedEvent{})
	// Check if there was an epoch transition.
	epochChanged, epoch := app.state.EpochChanged(ctx)

	state := roothashState.NewMutableState(ctx.State())

	switch {
	case epochChanged, rescheduled:
		return app.onCommitteeChanged(ctx, state, epoch)
	}

	return nil
}

func (app *Application) onCommitteeChanged(ctx *api.Context, state *roothashState.MutableState, epoch beacon.EpochTime) error {
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
		if rtState.LastBlock != nil {
			if round := rtState.LastBlock.Header.Round; round > params.MaxEvidenceAge {
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

		// Prepare new runtime committee based on what the scheduler did.
		committee, err := schedState.Committee(ctx, scheduler.KindComputeExecutor, rt.ID)
		if err != nil {
			ctx.Logger().Error("failed to get executor committee from scheduler",
				"err", err,
				"runtime", rt.ID,
			)
			return err
		}
		if committee == nil {
			ctx.Logger().Warn("no executor committee",
				"runtime", rt.ID,
			)
		}

		// If there are no committees for this runtime, suspend the runtime as this
		// means that there is noone to pay the maintenance fees.
		//
		// Also suspend the runtime in case the registering entity no longer has enough stake to
		// cover the entity and runtime deposits (this check is skipped if the runtime would be
		// suspended anyway due to nobody being there to pay maintenance fees).
		sufficientStake := true
		if committee != nil && !params.DebugBypassStake && rt.GovernanceModel != registry.GovernanceConsensus {
			acctAddr, ok := rt.StakingAddress()
			if !ok {
				// This should never happen.
				ctx.Logger().Error("unknown runtime governance model",
					"rt_id", rt.ID,
					"gov_model", rt.GovernanceModel,
				)
				return fmt.Errorf("unknown runtime governance model on runtime %s: %s", rt.ID, rt.GovernanceModel)
			}

			if err = stakeAcc.CheckStakeClaims(*acctAddr); err != nil {
				ctx.Logger().Debug("insufficient stake for runtime operation",
					"err", err,
					"entity", rt.EntityID,
					"account", *acctAddr,
				)
				sufficientStake = false
			}
		}
		suspend := committee == nil || !sufficientStake && !params.DebugDoNotSuspendRuntimes

		switch suspend {
		case true:
			ctx.Logger().Debug("suspending runtime, maintenance fees not paid or owner debonded",
				"runtime_id", rt.ID,
				"epoch", epoch,
			)

			if err = regState.SuspendRuntime(ctx, rt.ID); err != nil {
				return err
			}

			// Emit an empty block signalling that the runtime was suspended.
			if err = app.finalizeBlock(ctx, rtState, block.Suspended, nil); err != nil {
				return fmt.Errorf("failed to emit empty block: %w", err)
			}

			rtState.Suspended = true
			rtState.Committee = nil
		case false:
			ctx.Logger().Debug("updating committee for runtime",
				"runtime_id", rt.ID,
				"epoch", epoch,
				"committee", committee,
			)

			// Emit an empty block signaling epoch transition. This is required so that
			// the clients can be sure what state is final when an epoch transition occurs.
			if err = app.finalizeBlock(ctx, rtState, block.EpochTransition, nil); err != nil {
				return fmt.Errorf("failed to emit empty block: %w", err)
			}

			// Warning: Non-suspended runtimes can still have a nil committee.
			rtState.Suspended = false
			rtState.Committee = committee
		}

		// Clear liveness statistics.
		rtState.LivenessStatistics = nil
		// Update the runtime descriptor to the latest per-epoch value.
		rtState.Runtime = rt

		if err = state.SetRuntimeState(ctx, rtState); err != nil {
			return fmt.Errorf("failed to set runtime state: %w", err)
		}
	}

	return nil
}

// ExecuteMessage implements api.MessageSubscriber.
func (app *Application) ExecuteMessage(ctx *api.Context, kind, msg any) (any, error) {
	switch kind {
	case registryApi.MessageNewRuntimeRegistered:
		// A new runtime has been registered.
		if ctx.IsInitChain() {
			// Ignore messages emitted during InitChain as we handle these separately.
			return nil, nil
		}
		rt := msg.(*registry.Runtime)

		ctx.Logger().Debug("ExecuteMessage: new runtime",
			"runtime", rt.ID,
		)

		return nil, app.onNewRuntime(ctx, rt, nil, false)
	case registryApi.MessageRuntimeUpdated:
		// A runtime registration has been updated or a new runtime has been registered.
		if ctx.IsInitChain() {
			// Ignore messages emitted during InitChain as we handle these separately.
			return nil, nil
		}
		return nil, app.verifyRuntimeUpdate(ctx, msg.(*registry.Runtime))
	case registryApi.MessageRuntimeResumed:
		// A previously suspended runtime has been resumed.
		return nil, nil
	case roothashApi.RuntimeMessageNoop:
		// Noop message always succeeds.
		return nil, nil
	case schedulerApi.MessageBeforeSchedule:
		// Scheduler is about to perform scheduling. Process liveness statistics to make sure they
		// get taken into account for the next election.
		return app.doBeforeSchedule(ctx, msg)
	case governanceApi.MessageValidateParameterChanges:
		// A change parameters proposal is about to be submitted. Validate changes.
		return app.changeParameters(ctx, msg, false)
	case governanceApi.MessageChangeParameters:
		// A change parameters proposal has just been accepted and closed. Validate and apply
		// changes.
		return app.changeParameters(ctx, msg, true)
	default:
		return nil, roothash.ErrInvalidArgument
	}
}

func (app *Application) verifyRuntimeUpdate(ctx *api.Context, rt *registry.Runtime) error {
	state := roothashState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}

	return roothash.VerifyRuntimeParameters(rt, params)
}

// ExecuteTx implements api.Application.
func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	state := roothashState.NewMutableState(ctx.State())

	ctx.SetPriority(AppPriority)

	switch tx.Method {
	case roothash.MethodExecutorCommit:
		var xc roothash.ExecutorCommit
		if err := cbor.Unmarshal(tx.Body, &xc); err != nil {
			return roothash.ErrInvalidArgument
		}

		return app.executorCommit(ctx, state, &xc)
	case roothash.MethodEvidence:
		var ev roothash.Evidence
		if err := cbor.Unmarshal(tx.Body, &ev); err != nil {
			return roothash.ErrInvalidArgument
		}

		return app.submitEvidence(ctx, state, &ev)
	case roothash.MethodSubmitMsg:
		var msg roothash.SubmitMsg
		if err := cbor.Unmarshal(tx.Body, &msg); err != nil {
			return roothash.ErrInvalidArgument
		}

		return app.submitMsg(ctx, state, &msg)
	default:
		return roothash.ErrInvalidArgument
	}
}

func (app *Application) onNewRuntime(ctx *api.Context, runtime *registry.Runtime, genesis *roothash.Genesis, suspended bool) error {
	if !runtime.IsCompute() {
		ctx.Logger().Debug("onNewRuntime: ignoring non-compute runtime",
			"runtime", runtime,
		)
		return nil
	}

	// Check if state already exists for the given runtime.
	state := roothashState.NewMutableState(ctx.State())
	_, err := state.RuntimeState(ctx, runtime.ID)
	switch err {
	case nil:
		ctx.Logger().Debug("onNewRuntime: state for runtime already exists",
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
		Runtime:          runtime,
		Suspended:        true,
		LastBlock:        genesisBlock,
		LastBlockHeight:  ctx.BlockHeight() + 1, // Current height is ctx.BlockHeight() + 1
		LastNormalRound:  genesisBlock.Header.Round,
		LastNormalHeight: ctx.BlockHeight() + 1, // Current height is ctx.BlockHeight() + 1
		GenesisBlock:     genesisBlock,
		NextTimeout:      roothash.TimeoutNever,
	})
	if err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	ctx.Logger().Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	ctx.EmitEvent(
		api.NewEventBuilder(app.Name()).
			TypedAttribute(&roothash.FinalizedEvent{Round: genesisBlock.Header.Round}).
			TypedAttribute(&roothash.RuntimeIDAttribute{ID: runtime.ID}),
	)
	return nil
}

// EndBlock implements api.Application.
func (app *Application) EndBlock(ctx *api.Context) (types.ResponseEndBlock, error) {
	if err := app.tryFinalizeRounds(ctx); err != nil {
		return types.ResponseEndBlock{}, err
	}

	if err := app.processRoundTimeouts(ctx); err != nil {
		return types.ResponseEndBlock{}, err
	}

	return types.ResponseEndBlock{}, nil
}
