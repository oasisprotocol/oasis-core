// Package roothash implements the roothash application.
package roothash

import (
	"encoding/hex"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/apps/registry"
)

const (
	roundTimeout = 10 * time.Second
)

var (
	errNoSuchContract = errors.New("tendermint/roothash: no such contract")
	errNoRound        = errors.New("tendermint/roothash: no round in progress")

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

	contract, err := state.GetContractState(request.ID)
	if err != nil {
		return nil, err
	}
	if contract == nil {
		return nil, errNoSuchContract
	}

	block := contract.CurrentBlock.MarshalCBOR()

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

	for _, contract := range state.GetContracts() {
		committees, err := app.scheduler.GetBlockCommittees(context.Background(), contract.ID, app.state.BlockHeight())
		if err != nil {
			app.logger.Error("checkCommittees: failed to get committees from scheduler",
				"err", err,
				"contract", contract.ID,
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
				"contract", contract.ID,
			)
			continue
		}

		app.logger.Debug("checkCommittees: updating committee for contract",
			"contract", contract.ID,
		)

		// If the committee is the "same", ignore this.
		//
		// TODO: Use a better check to allow for things like rescheduling.
		round := contract.Round
		if round != nil && round.RoundState.Committee.ValidFor == committee.ValidFor {
			app.logger.Debug("checkCommittees: duplicate committee or reschedule, ignoring",
				"contract", contract.ID,
				"epoch", committee.ValidFor,
			)
			continue
		}

		// Transition the round.
		block := contract.CurrentBlock
		blockNr, _ := block.Header.Round.ToU64()

		app.logger.Debug("checkCommittees: new committee, transitioning round",
			"contract", contract.ID,
			"epoch", committee.ValidFor,
			"round", blockNr,
		)

		contract.Timer.Stop(ctx)
		contract.Round = newRound(committee, block)
		state.UpdateContractState(contract)
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
		if contract := ctx.GetTag(api.TagRegistryContractRegistered); contract != nil {
			app.logger.Debug("ForeignDeliverTx: new contract",
				"contract", hex.EncodeToString(contract),
			)

			tree := app.state.DeliverTxTree()

			// New contract has been registered, create its roothash state.
			regState := registry.NewMutableState(tree)
			contract, err := regState.GetContract(contract)
			if err != nil {
				return errors.Wrap(err, "roothash: failed to fetch new contract")
			}

			state := NewMutableState(tree)

			// Check if state already exists for the given contract.
			cs, _ := state.GetContractState(contract.ID)
			if cs != nil {
				// Do not propagate the error as this would fail the transaction.
				app.logger.Warn("ForeignDeliverTx: state for contract already exists",
					"contract", contract,
				)
				return nil
			}

			// Create genesis block.
			block := newGenesisBlock(ctx, contract.ID)

			// Create new state containing the genesis block.
			timerCtx := &timerContext{ID: contract.ID}
			state.UpdateContractState(&ContractState{
				ID:           contract.ID,
				CurrentBlock: block,
				Timer:        *abci.NewTimer(ctx, app, "round-"+contract.ID.String(), timerCtx.MarshalCBOR()),
			})

			app.logger.Debug("ForeignDeliverTx: created genesis state for contract",
				"contract", contract,
			)

			// This transaction now also includes a new block for the given contract.
			id, _ := contract.ID.MarshalBinary()
			ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
			ctx.EmitTag(api.TagRootHashID, id)
			ctx.EmitTag(api.TagRootHashFinalized, []byte("0"))
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
	cs, err := state.GetContractState(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		panic(err)
	}

	regState := registry.NewMutableState(tree)
	contract, err := regState.GetContract(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to fetch contract",
			"err", err,
		)
		panic(err)
	}

	latestBlock := cs.CurrentBlock
	if blockNr, _ := latestBlock.Header.Round.ToU64(); blockNr != tCtx.Round {
		app.logger.Error("FireTimer: spurious timeout detected",
			"contract", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", blockNr,
		)

		// XXX: This should just disarm the timer and attempt to continue
		// in production, but tracking down #1047 is more important.
		panic("BUG: spurious timeout, check logs")

		// timer.Stop(ctx)
		// return
	}

	app.logger.Warn("FireTimer: round timeout expired, forcing finalization",
		"contract", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.UpdateContractState(cs)
	cs.Round.DidTimeout = true
	app.tryFinalize(ctx, contract, cs, true)
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
	commit *roothash.Commitment,
) error {
	contractState, err := state.GetContractState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch contract state")
	}
	if contractState == nil {
		return errNoSuchContract
	}

	regState := registry.NewMutableState(state.Tree())
	contract, err := regState.GetContract(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch contract")
	}

	var c commitment
	if err = c.fromCommitment(commit); err != nil {
		return errors.Wrap(err, "roothash: failed to unmarshal commitment")
	}

	if ctx.IsCheckOnly() {
		// If we are within CheckTx then we cannot do any further checks as epoch
		// transitions are only handled in BeginBlock.
		return nil
	}

	if contractState.Round == nil {
		app.logger.Error("commit recevied when no round in progress",
			"err", errNoRound,
		)
		return errNoRound
	}

	latestBlock := contractState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	defer state.UpdateContractState(contractState)

	// If the round was finalized, transition.
	if contractState.Round.RoundState.CurrentBlock.Header.Round != latestBlock.Header.Round {
		app.logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		contractState.Round = newRound(contractState.Round.RoundState.Committee, latestBlock)
	}

	// Add the commitment.
	if err = contractState.Round.addCommitment(app.storage, &c); err != nil {
		app.logger.Error("failed to add commitment to round",
			"err", err,
			"round", blockNr,
		)
		return err
	}

	// Try to finalize round.
	app.tryFinalize(ctx, contract, contractState, false)

	return nil
}

func (app *rootHashApplication) tryFinalize(
	ctx *abci.Context,
	contract *contract.Contract,
	contractState *ContractState,
	forced bool,
) { // nolint: gocyclo
	latestBlock := contractState.CurrentBlock
	blockNr, _ := latestBlock.Header.Round.ToU64()

	var rearmTimer bool
	defer func() {
		// Note: Unlike the Rust code, this pushes back the timer
		// each time forward progress is made.

		switch rearmTimer {
		case true: // (Re-)arm timer.
			app.logger.Debug("(re-)arming round timeout")

			timerCtx := &timerContext{
				ID:    contract.ID,
				Round: blockNr,
			}
			contractState.Timer.Reset(ctx, roundTimeout, timerCtx.MarshalCBOR())
		case false: // Disarm timer.
			app.logger.Debug("disarming round timeout")
			contractState.Timer.Stop(ctx)
		}
	}()

	state := contractState.Round.RoundState.State
	id, _ := contract.ID.MarshalBinary()

	if state == stateFinalized {
		app.logger.Error("attempted to finalize when block already finalized",
			"round", blockNr,
		)
		return
	}

	block, err := contractState.Round.tryFinalize(ctx, contract)
	switch err {
	case nil:
		// Round has been finalized.
		app.logger.Debug("finalized round",
			"round", blockNr,
		)

		contractState.CurrentBlock = block

		roundNr, _ := block.Header.Round.ToU64()
		roundStr := strconv.FormatUint(roundNr, 10)

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		ctx.EmitTag(api.TagRootHashID, id)
		ctx.EmitTag(api.TagRootHashFinalized, []byte(roundStr))
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
			err = contractState.Round.forceBackupTransition()
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

		event := roothash.DiscrepancyDetectedEvent{
			BatchHash:   &inputHash,
			BlockHeader: &latestBlock.Header,
		}

		ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
		ctx.EmitTag(api.TagRootHashID, id)
		ctx.EmitTag(api.TagRootHashDiscrepancyDetected, event.MarshalCBOR())

		// Re-arm the timer.  The rust code waits till the first discrepancy
		// commit to do this, but there is 0 guarantee that said commit will
		// come.
		rearmTimer = true
		return
	}

	// Something else went wrong.
	app.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	contractState.Round.reset()

	ctx.EmitTag(api.TagRootHashUpdate, api.TagRootHashUpdateValue)
	ctx.EmitTag(api.TagRootHashID, id)
	ctx.EmitTag(api.TagRootHashRoundFailed, []byte(err.Error()))
}

// New constructs a new roothash application instance.
func New(
	timeSource epochtime.BlockBackend,
	scheduler scheduler.BlockBackend,
	storage storage.Backend,
) abci.Application {
	return &rootHashApplication{
		logger:     logging.GetLogger("tendermint/roothash"),
		timeSource: timeSource,
		scheduler:  scheduler,
		storage:    storage,
	}
}

func newGenesisBlock(ctx *abci.Context, id signature.PublicKey) *roothash.Block {
	var blk roothash.Block

	blk.Header.Version = 0
	_ = blk.Header.Namespace.UnmarshalBinary(id[:])
	blk.Header.Timestamp = uint64(ctx.Now().Unix())
	blk.Header.InputHash.Empty()
	blk.Header.OutputHash.Empty()
	blk.Header.StateRoot.Empty()

	return &blk
}
