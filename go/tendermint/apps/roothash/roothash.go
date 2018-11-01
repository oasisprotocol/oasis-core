// Package roothash implements the roothash application.
package roothash

import (
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
)

var (
	errNoSuchRuntime = errors.New("tendermint/roothash: no such runtime")
	errNoRound       = errors.New("tendermint/roothash: no round in progress")

	_ abci.Application = (*rootHashApplication)(nil)
)

type timerContext struct {
	ID    signature.PublicKey `codec:"id"`
	Round uint64              `codec:"round"`
}

func (ctx *timerContext) MarshalCBOR() []byte {
	return cbor.Marshal(ctx)
}

func (ctx *timerContext) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, ctx)
}

type rootHashApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
	scheduler  scheduler.BlockBackend
	storage    storage.Backend

	// If a runtime with one of these IDs would be initialized,
	// start with the given block as the genesis block. For other
	// runtime, generate an "empty" genesis block.
	genesisBlocks map[signature.MapKey]*block.Block

	roundTimeout time.Duration
}

func (app *rootHashApplication) Name() string {
	return api.RootHashAppName
}

func (app *rootHashApplication) TransactionTag() byte {
	return api.RootHashTransactionTag
}

func (app *rootHashApplication) Blessed() bool {
	return false
}

func (app *rootHashApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(api.QueryRootHashGetLatestBlock, &api.QueryGetLatestBlock{}, app.queryGetLatestBlock)
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *rootHashApplication) GetState(height int64) (interface{}, error) {
	return NewImmutableState(app.state, height)
}

func (app *rootHashApplication) queryGetLatestBlock(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetLatestBlock)
	state := s.(*ImmutableState)

	runtime, err := state.GetRuntimeState(request.ID)
	if err != nil {
		return nil, err
	}
	if runtime == nil {
		return nil, errNoSuchRuntime
	}

	block := runtime.CurrentBlock.MarshalCBOR()

	return block, nil
}

func (app *rootHashApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRootHash{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	if err := app.executeTx(ctx, app.state.CheckTxTree(), request); err != nil {
		return err
	}

	return nil
}

func (app *rootHashApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *rootHashApplication) InitChain(request types.RequestInitChain) types.ResponseInitChain {
	return types.ResponseInitChain{}
}

func (app *rootHashApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
	app.checkCommittees(ctx)
}

func (app *rootHashApplication) checkCommittees(ctx *abci.Context) { // nolint: gocyclo
	// Only perform checks on epoch changes.
	if app.state.BlockHeight() == 0 {
		return
	}
	previousEpoch, _, err := app.timeSource.GetBlockEpoch(context.Background(), app.state.BlockHeight()-1)
	if err != nil {
		app.logger.Error("checkCommittees: failed to get previous epoch",
			"err", err,
		)
		return
	}
	currentEpoch, _, err := app.timeSource.GetBlockEpoch(context.Background(), app.state.BlockHeight())
	if err != nil {
		app.logger.Error("checkCommittees: failed to get current epoch",
			"err", err,
		)
		return
	}
	if previousEpoch == currentEpoch {
		return
	}

	app.logger.Debug("checkCommittees: epoch transition, updating rounds",
		"prev_epoch", previousEpoch,
		"epoch", currentEpoch,
	)

	state := NewMutableState(app.state.DeliverTxTree())

	for _, runtime := range state.GetRuntimes() {
		committees, err := app.scheduler.GetBlockCommittees(context.Background(), runtime.ID, app.state.BlockHeight())
		if err != nil {
			app.logger.Error("checkCommittees: failed to get committees from scheduler",
				"err", err,
				"runtime", runtime.ID,
			)
			continue
		}

		var committee *scheduler.Committee
		for _, c := range committees {
			if c.Kind == scheduler.Compute {
				committee = c
				break
			}
		}
		if committee == nil {
			app.logger.Error("checkCommittees: scheduler did not give us a compute committee",
				"runtime", runtime.ID,
			)
			continue
		}

		app.logger.Debug("checkCommittees: updating committee for runtime",
			"runtime", runtime.ID,
		)

		// If the committee is the "same", ignore this.
		//
		// TODO: Use a better check to allow for things like rescheduling.
		round := runtime.Round
		if round != nil && round.RoundState.Committee.ValidFor == committee.ValidFor {
			app.logger.Debug("checkCommittees: duplicate committee or reschedule, ignoring",
				"runtime", runtime.ID,
				"epoch", committee.ValidFor,
			)
			continue
		}

		// Transition the round.
		block := runtime.CurrentBlock
		blockNr, _ := block.Header.Round.ToU64()

		app.logger.Debug("checkCommittees: new committee, transitioning round",
			"runtime", runtime.ID,
			"epoch", committee.ValidFor,
			"round", blockNr,
		)

		runtime.Timer.Stop(ctx)
		runtime.Round = newRound(committee, block)
		state.UpdateRuntimeState(runtime)
	}
}

func (app *rootHashApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &api.TxRootHash{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *rootHashApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	switch other.Name() {
	case api.RegistryAppName:
		if runtime := ctx.GetTag(api.TagRegistryRuntimeRegistered); runtime != nil {
			app.logger.Debug("ForeignDeliverTx: new runtime",
				"runtime", hex.EncodeToString(runtime),
			)

			tree := app.state.DeliverTxTree()

			// New runtime has been registered, create its roothash state.
			regState := registryapp.NewMutableState(tree)
			runtime, err := regState.GetRuntime(runtime)
			if err != nil {
				return errors.Wrap(err, "roothash: failed to fetch new runtime")
			}

			state := NewMutableState(tree)

			// Check if state already exists for the given runtime.
			cs, _ := state.GetRuntimeState(runtime.ID)
			if cs != nil {
				// Do not propagate the error as this would fail the transaction.
				app.logger.Warn("ForeignDeliverTx: state for runtime already exists",
					"runtime", runtime,
				)
				return nil
			}

			// Create genesis block.
			genesisBlock := app.genesisBlocks[runtime.ID.ToMapKey()]
			if genesisBlock == nil {
				now := ctx.Now().Unix()
				genesisBlock = block.NewGenesisBlock(runtime.ID, uint64(now))
			}

			// Create new state containing the genesis block.
			timerCtx := &timerContext{ID: runtime.ID}
			state.UpdateRuntimeState(&RuntimeState{
				ID:           runtime.ID,
				CurrentBlock: genesisBlock,
				Timer:        *abci.NewTimer(ctx, app, "round-"+runtime.ID.String(), timerCtx.MarshalCBOR()),
			})

			app.logger.Debug("ForeignDeliverTx: created genesis state for runtime",
				"runtime", runtime,
			)

			// This transaction now also includes a new block for the given runtime.
			id, _ := runtime.ID.MarshalBinary()
			ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
			tagV := api.ValueRootHashFinalized{
				ID:    id,
				Round: 0,
			}
			ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
		}
	}

	return nil
}

func (app *rootHashApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

func (app *rootHashApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
	var tCtx timerContext
	if err := tCtx.UnmarshalCBOR(timer.Data()); err != nil {
		panic(err)
	}

	tree := app.state.DeliverTxTree()
	state := NewMutableState(tree)
	cs, err := state.GetRuntimeState(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		panic(err)
	}

	regState := registryapp.NewMutableState(tree)
	runtime, err := regState.GetRuntime(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to fetch runtime",
			"err", err,
		)
		panic(err)
	}

	latestBlock := cs.CurrentBlock
	if blockNr, _ := latestBlock.Header.Round.ToU64(); blockNr != tCtx.Round {
		// Note: This should NEVER happen, but it does and causes massive
		// problems (#1047).
		app.logger.Error("FireTimer: spurious timeout detected",
			"runtime", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", blockNr,
		)

		timer.Stop(ctx)

		// WARNING: `timer` != cs.Timer, while the ID shouldn't change
		// and the difference in structs should be harmless, be extra
		// defensive till we root cause and fix the timer problems.

		var csCtx timerContext
		if err := csCtx.UnmarshalCBOR(cs.Timer.Data()); err != nil {
			app.logger.Error("FireTimer: Failed to unmarshal runtime state timer",
				"err", err,
			)
			return
		}

		app.logger.Error("FireTimer: runtime state timer",
			"runtime", csCtx.ID,
			"timer_round", csCtx.Round,
		)

		cs.Timer.Stop(ctx)
		state.UpdateRuntimeState(cs)

		return
	}

	app.logger.Warn("FireTimer: round timeout expired, forcing finalization",
		"runtime", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.UpdateRuntimeState(cs)
	cs.Round.DidTimeout = true
	app.tryFinalize(ctx, runtime, cs, true)
}

func (app *rootHashApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *api.TxRootHash,
) error {
	state := NewMutableState(tree)

	if tx.TxCommit != nil {
		return app.commit(ctx, state, tx.TxCommit.ID, &tx.TxCommit.Commitment)
	}
	return roothash.ErrInvalidArgument
}

func (app *rootHashApplication) commit(
	ctx *abci.Context,
	state *MutableState,
	id signature.PublicKey,
	commit *roothash.OpaqueCommitment,
) error {
	runtimeState, err := state.GetRuntimeState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime state")
	}
	if runtimeState == nil {
		return errNoSuchRuntime
	}

	regState := registryapp.NewMutableState(state.Tree())
	runtime, err := regState.GetRuntime(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime")
	}

	var c commitment.Commitment
	if err = c.FromOpaqueCommitment(commit); err != nil {
		return errors.Wrap(err, "roothash: failed to unmarshal commitment")
	}

	if ctx.IsCheckOnly() {
		// If we are within CheckTx then we cannot do any further checks as epoch
		// transitions are only handled in BeginBlock.
		return nil
	}

	if runtimeState.Round == nil {
		app.logger.Error("commit recevied when no round in progress",
			"err", errNoRound,
		)
		return errNoRound
	}

	latestBlock := runtimeState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	defer state.UpdateRuntimeState(runtimeState)

	// If the round was finalized, transition.
	if runtimeState.Round.RoundState.CurrentBlock.Header.Round != latestBlock.Header.Round {
		app.logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		runtimeState.Round = newRound(runtimeState.Round.RoundState.Committee, latestBlock)
	}

	// Add the commitment.
	if err = runtimeState.Round.addCommitment(app.storage, &c); err != nil {
		app.logger.Error("failed to add commitment to round",
			"err", err,
			"round", blockNr,
		)
		return err
	}

	// Try to finalize round.
	app.tryFinalize(ctx, runtime, runtimeState, false)

	return nil
}

func (app *rootHashApplication) tryFinalize(
	ctx *abci.Context,
	runtime *registry.Runtime,
	runtimeState *RuntimeState,
	forced bool,
) { // nolint: gocyclo
	latestBlock := runtimeState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	var rearmTimer bool
	defer func() {
		// Note: Unlike the Rust code, this pushes back the timer
		// each time forward progress is made.

		switch rearmTimer {
		case true: // (Re-)arm timer.
			app.logger.Debug("(re-)arming round timeout")

			timerCtx := &timerContext{
				ID:    runtime.ID,
				Round: blockNr,
			}
			runtimeState.Timer.Reset(ctx, app.roundTimeout, timerCtx.MarshalCBOR())
		case false: // Disarm timer.
			app.logger.Debug("disarming round timeout")
			runtimeState.Timer.Stop(ctx)
		}
	}()

	state := runtimeState.Round.RoundState.State
	id, _ := runtime.ID.MarshalBinary()

	if state == stateFinalized {
		app.logger.Error("attempted to finalize when block already finalized",
			"round", blockNr,
		)
		return
	}

	blk, err := runtimeState.Round.tryFinalize(ctx, runtime)
	switch err {
	case nil:
		// Round has been finalized.
		app.logger.Debug("finalized round",
			"round", blockNr,
		)

		runtimeState.CurrentBlock = blk

		roundNr, _ := blk.Header.Round.ToU64()

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		tagV := api.ValueRootHashFinalized{
			ID:    id,
			Round: roundNr,
		}
		ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
		return
	case errStillWaiting:
		if forced {
			if state == stateDiscrepancyWaitingCommitments {
				// This was a forced finalization call due to timeout,
				// and the round was in the discrepancy state.  Give up.
				app.logger.Error("failed to finalize discrepancy committee on timeout",
					"round", blockNr,
				)
				break
			}

			// This is the fast path and the round timer expired.
			//
			// Transition to the discrepancy state so the backup workers
			// process the round, assuming that is is possible to do so.
			app.logger.Error("failed to finalize committee on timeout",
				"round", blockNr,
			)
			err = runtimeState.Round.forceBackupTransition()
			break
		}

		app.logger.Debug("insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		rearmTimer = true
		return
	default:
	}

	if dErr, ok := (err).(errDiscrepancyDetected); ok {
		inputHash := hash.Hash(dErr)

		app.logger.Warn("discrepancy detected",
			"round", blockNr,
			"input_hash", inputHash,
		)

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		tagV := api.ValueRootHashDiscrepancyDetected{
			ID: id,
			Event: roothash.DiscrepancyDetectedEvent{
				BatchHash:   &inputHash,
				BlockHeader: &latestBlock.Header,
			},
		}
		ctx.EmitTag(api.TagRootHashDiscrepancyDetected, tagV.MarshalCBOR())

		// Re-arm the timer.  The rust code waits till the first discrepancy
		// commit to do this, but there is 0 guarantee that said commit will
		// come.
		rearmTimer = true
		return
	}

	// Something else went wrong, emit empty error block.
	app.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	blk = block.NewEmptyBlock(latestBlock, uint64(ctx.Now().Unix()), block.RoundFailed)
	runtimeState.Round.populateFinalizedBlock(blk)

	runtimeState.CurrentBlock = blk

	roundNr, _ := blk.Header.Round.ToU64()

	ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
	tagV := api.ValueRootHashFinalized{
		ID:    id,
		Round: roundNr,
	}
	ctx.EmitTag(api.TagRootHashFinalized, tagV.MarshalCBOR())
}

// New constructs a new roothash application instance.
func New(
	timeSource epochtime.BlockBackend,
	scheduler scheduler.BlockBackend,
	storage storage.Backend,
	genesisBlocks map[signature.MapKey]*block.Block,
	roundTimeout time.Duration,
) abci.Application {
	return &rootHashApplication{
		logger:        logging.GetLogger("tendermint/roothash"),
		timeSource:    timeSource,
		scheduler:     scheduler,
		storage:       storage,
		genesisBlocks: genesisBlocks,
		roundTimeout:  roundTimeout,
	}
}
