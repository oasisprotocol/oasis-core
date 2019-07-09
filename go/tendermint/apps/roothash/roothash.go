// Package roothash implements the roothash application.
package roothash

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
	schedulerapp "github.com/oasislabs/ekiden/go/tendermint/apps/scheduler"
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
	ctx    context.Context
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.Backend
	beacon     beacon.Backend

	roundTimeout time.Duration
}

func (app *rootHashApplication) Name() string {
	return AppName
}

func (app *rootHashApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *rootHashApplication) Blessed() bool {
	return false
}

func (app *rootHashApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetLatestBlock, api.QueryGetByIDRequest{}, app.queryGetLatestBlock)
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *rootHashApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *rootHashApplication) queryGetLatestBlock(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)

	runtime, err := state.getRuntimeState(request.ID)
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
	request := &Tx{}
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

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.RootHash

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	tree := app.state.DeliverTxTree()

	regState := registryapp.NewMutableState(tree)
	runtimes, _ := regState.GetRuntimes()
	for _, v := range runtimes {
		app.logger.Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		app.onNewRuntime(ctx, tree, v, &st)
	}

	return nil
}

func (app *rootHashApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// Only perform checks on epoch changes.
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onEpochChange(ctx, epoch)
	}
	return nil
}

func (app *rootHashApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error { // nolint: gocyclo
	tree := app.state.DeliverTxTree()
	state := newMutableState(tree)

	// Query the updated runtime list.
	regState := registryapp.NewMutableState(tree)
	runtimes, _ := regState.GetRuntimes()
	newDescriptors := make(map[signature.MapKey]*registry.Runtime)
	for _, v := range runtimes {
		if v.Kind == registry.KindCompute {
			newDescriptors[v.ID.ToMapKey()] = v
		}
	}

	schedState := schedulerapp.NewMutableState(tree)
	for _, rtState := range state.getRuntimes() {
		rtID := rtState.Runtime.ID

		if !rtState.Runtime.IsCompute() {
			app.logger.Debug("checkCommittees: skipping non-compute runtime",
				"runtime", rtID,
			)
			continue
		}

		// There will later be multiple compute committees.
		computeCommittee, err := schedState.GetCommittee(scheduler.KindCompute, rtID)
		if err != nil {
			app.logger.Error("checkCommittees: failed to get compute committee from scheduler",
				"err", err,
				"runtime", rtID,
			)
			continue
		}
		if computeCommittee == nil {
			app.logger.Warn("checkCommittees: no compute committee this epoch",
				"runtime", rtID,
			)
			continue
		}
		computeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
		for idx, n := range computeCommittee.Members {
			var nodeRuntime *node.Runtime
			node, err1 := regState.GetNode(n.PublicKey)
			if err1 != nil {
				return errors.Wrap(err1, "checkCommittees: failed to query node")
			}
			for _, r := range node.Runtimes {
				if !r.ID.Equal(rtID) {
					continue
				}
				nodeRuntime = r
				break
			}
			if nodeRuntime == nil {
				// We currently prevent this case throughout the rest of the system.
				// Still, it's prudent to check.
				app.logger.Warn("checkCommittees: committee member not registered with this runtime",
					"node", n.PublicKey,
				)
				continue
			}
			computeNodeInfo[n.PublicKey.ToMapKey()] = commitment.NodeInfo{
				CommitteeNode: idx,
				Runtime:       nodeRuntime,
			}
		}
		computePool := &commitment.MultiPool{
			Committees: map[hash.Hash]*commitment.Pool{
				computeCommittee.EncodedMembersHash(): &commitment.Pool{
					Runtime:   rtState.Runtime,
					Committee: computeCommittee,
					NodeInfo:  computeNodeInfo,
				},
			},
		}

		mergeCommittee, err := schedState.GetCommittee(scheduler.KindMerge, rtID)
		if err != nil {
			app.logger.Error("checkCommittees: failed to get merge committee from scheduler",
				"err", err,
				"runtime", rtID,
			)
			continue
		}
		mergeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
		for idx, n := range mergeCommittee.Members {
			mergeNodeInfo[n.PublicKey.ToMapKey()] = commitment.NodeInfo{
				CommitteeNode: idx,
			}
		}
		mergePool := &commitment.Pool{
			Runtime:   rtState.Runtime,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		}

		app.logger.Debug("checkCommittees: updating committee for runtime",
			"runtime", rtID,
		)

		// If the committee is the "same", ignore this.
		//
		// TODO: Use a better check to allow for things like rescheduling.
		round := rtState.Round
		if round != nil && round.MergePool.Committee.ValidFor == mergePool.Committee.ValidFor {
			app.logger.Debug("checkCommittees: duplicate committee or reschedule, ignoring",
				"runtime", rtID,
				"epoch", mergePool.Committee.ValidFor,
			)
			mk := rtID.ToMapKey()
			if _, ok := newDescriptors[mk]; ok {
				delete(newDescriptors, rtID.ToMapKey())
			}
			continue
		}

		// Transition the round.
		blk := rtState.CurrentBlock
		blockNr := blk.Header.Round

		app.logger.Debug("checkCommittees: new committee, transitioning round",
			"runtime", rtID,
			"epoch", mergePool.Committee.ValidFor,
			"round", blockNr,
		)

		rtState.Timer.Stop(ctx)
		rtState.Round = newRound(computePool, mergePool, blk)

		// Emit an empty epoch transition block in the new round. This is required so that
		// the clients can be sure what state is final when an epoch transition occurs.
		app.emitEmptyBlock(ctx, rtState, block.EpochTransition)

		mk := rtID.ToMapKey()
		if rt, ok := newDescriptors[mk]; ok {
			// Update the runtime descriptor to the latest per-epoch value.
			rtState.Runtime = rt
			delete(newDescriptors, mk)
		}

		state.updateRuntimeState(rtState)
	}

	// Just because a runtime didn't have committees, it doesn't mean that
	// it's state does not need to be updated. Do so now where possible.
	for _, v := range newDescriptors {
		rtState, err := state.getRuntimeState(v.ID)
		if err != nil {
			app.logger.Warn("onEpochChange: unknown runtime in update pass",
				"runtime", v,
			)
			continue
		}

		rtState.Runtime = v
		state.updateRuntimeState(rtState)
	}

	return nil
}

func (app *rootHashApplication) emitEmptyBlock(ctx *abci.Context, runtime *runtimeState, hdrType block.HeaderType) {
	blk := block.NewEmptyBlock(runtime.CurrentBlock, uint64(ctx.Now().Unix()), hdrType)

	runtime.CurrentBlock = blk

	ctx.EmitTag(TagUpdate, TagUpdateValue)
	tagV := ValueFinalized{
		ID:    runtime.Runtime.ID,
		Round: blk.Header.Round,
	}
	ctx.EmitTag(TagFinalized, tagV.MarshalCBOR())
}

func (app *rootHashApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *rootHashApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	var st *roothash.Genesis
	ensureGenesis := func() {
		st = &app.state.Genesis().RootHash
	}

	switch other.Name() {
	case registryapp.AppName:
		for _, pair := range ctx.Tags() {
			if bytes.Equal(pair.GetKey(), registryapp.TagRuntimeRegistered) {
				runtime := pair.GetValue()

				app.logger.Debug("ForeignDeliverTx: new runtime",
					"runtime", hex.EncodeToString(runtime),
				)

				tree := app.state.DeliverTxTree()

				// New runtime has been registered, create its roothash state.
				regState := registryapp.NewMutableState(tree)
				rt, err := regState.GetRuntime(runtime)
				if err != nil {
					return errors.Wrap(err, "roothash: failed to fetch new runtime")
				}

				ensureGenesis()
				app.onNewRuntime(ctx, tree, rt, st)
			}
		}
	}

	return nil
}

func (app *rootHashApplication) onNewRuntime(ctx *abci.Context, tree *iavl.MutableTree, runtime *registry.Runtime, genesis *roothash.Genesis) {
	state := newMutableState(tree)

	if !runtime.IsCompute() {
		app.logger.Warn("onNewRuntime: ignoring non-compute runtime",
			"runtime", runtime,
		)
		return
	}

	// Check if state already exists for the given runtime.
	rtState, _ := state.getRuntimeState(runtime.ID)
	if rtState != nil {
		// Do not propagate the error as this would fail the transaction.
		app.logger.Warn("onNewRuntime: state for runtime already exists",
			"runtime", runtime,
		)
		return
	}

	// Create genesis block.
	genesisBlock := genesis.Blocks[runtime.ID.ToMapKey()]
	if genesisBlock == nil {
		now := ctx.Now().Unix()
		genesisBlock = block.NewGenesisBlock(runtime.ID, uint64(now))
		if !runtime.Genesis.StateRoot.IsEmpty() {
			genesisBlock.Header.StateRoot = runtime.Genesis.StateRoot
		}
	}

	// Create new state containing the genesis block.
	timerCtx := &timerContext{ID: runtime.ID}
	state.updateRuntimeState(&runtimeState{
		Runtime:      runtime,
		CurrentBlock: genesisBlock,
		Timer:        *abci.NewTimer(ctx, app, "round-"+runtime.ID.String(), timerCtx.MarshalCBOR()),
	})

	app.logger.Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	// This transaction now also includes a new block for the given runtime.
	id, _ := runtime.ID.MarshalBinary()
	ctx.EmitTag(TagUpdate, TagUpdateValue)
	tagV := ValueFinalized{
		ID:    id,
		Round: genesisBlock.Header.Round,
	}
	ctx.EmitTag(TagFinalized, tagV.MarshalCBOR())
}

func (app *rootHashApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *rootHashApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
	var tCtx timerContext
	if err := tCtx.UnmarshalCBOR(timer.Data()); err != nil {
		panic(err)
	}

	tree := app.state.DeliverTxTree()
	state := newMutableState(tree)
	rtState, err := state.getRuntimeState(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		panic(err)
	}
	runtime := rtState.Runtime

	latestBlock := rtState.CurrentBlock
	if latestBlock.Header.Round != tCtx.Round {
		// Note: This should NEVER happen, but it does and causes massive
		// problems (#1047).
		app.logger.Error("FireTimer: spurious timeout detected",
			"runtime", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", latestBlock.Header.Round,
		)

		timer.Stop(ctx)

		// WARNING: `timer` != rtState.Timer, while the ID shouldn't
		// change and the difference in structs should be harmless, there
		// is nothing lost with being extra defensive.

		var rsCtx timerContext
		if err := rsCtx.UnmarshalCBOR(rtState.Timer.Data()); err != nil {
			app.logger.Error("FireTimer: Failed to unmarshal runtime state timer",
				"err", err,
			)
			return
		}

		app.logger.Error("FireTimer: runtime state timer",
			"runtime", rsCtx.ID,
			"timer_round", rsCtx.Round,
		)

		rtState.Timer.Stop(ctx)
		state.updateRuntimeState(rtState)

		return
	}

	app.logger.Warn("FireTimer: round timeout expired, forcing finalization",
		"runtime", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.updateRuntimeState(rtState)

	if rtState.Round.MergePool.IsTimeout(ctx.Now()) {
		app.tryFinalizeMerge(ctx, runtime, rtState, true)
	}
	for _, pool := range rtState.Round.ComputePool.GetTimeoutCommittees(ctx.Now()) {
		app.tryFinalizeCompute(ctx, runtime, rtState, pool, true)
	}
}

func (app *rootHashApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *Tx,
) error {
	state := newMutableState(tree)

	if tx.TxMergeCommit != nil {
		return app.commit(ctx, state, tx.TxMergeCommit.ID, tx)
	} else if tx.TxComputeCommit != nil {
		return app.commit(ctx, state, tx.TxComputeCommit.ID, tx)
	}
	return roothash.ErrInvalidArgument
}

func (app *rootHashApplication) commit(
	ctx *abci.Context,
	state *mutableState,
	id signature.PublicKey,
	tx *Tx,
) error {
	rtState, err := state.getRuntimeState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime state")
	}
	if rtState == nil {
		return errNoSuchRuntime
	}
	runtime := rtState.Runtime

	if ctx.IsCheckOnly() {
		// If we are within CheckTx then we cannot do any further checks as epoch
		// transitions are only handled in BeginBlock.
		return nil
	}

	if rtState.Round == nil {
		app.logger.Error("commit recevied when no round in progress",
			"err", errNoRound,
		)
		return errNoRound
	}

	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round

	defer state.updateRuntimeState(rtState)

	// If the round was finalized, transition.
	if rtState.Round.CurrentBlock.Header.Round != latestBlock.Header.Round {
		app.logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		rtState.Round.transition(latestBlock)
	}

	// Add the commitments.
	if tx.TxMergeCommit != nil {
		for _, commit := range tx.TxMergeCommit.Commits {
			if err = rtState.Round.addMergeCommitment(&commit); err != nil {
				app.logger.Error("failed to add merge commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}
		}

		// Try to finalize round.
		app.tryFinalizeMerge(ctx, runtime, rtState, false)
	} else if tx.TxComputeCommit != nil {
		pools := make(map[*commitment.Pool]bool)
		for _, commit := range tx.TxComputeCommit.Commits {
			var pool *commitment.Pool
			if pool, err = rtState.Round.addComputeCommitment(&commit); err != nil {
				app.logger.Error("failed to add compute commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}

			pools[pool] = true
		}

		for pool := range pools {
			app.tryFinalizeCompute(ctx, runtime, rtState, pool, false)
		}
	}

	return nil
}

func (app *rootHashApplication) updateTimer(
	ctx *abci.Context,
	runtime *registry.Runtime,
	rtState *runtimeState,
	blockNr uint64,
) {
	nextTimeout := rtState.Round.getNextTimeout()
	if nextTimeout.IsZero() {
		// Disarm timer.
		app.logger.Debug("disarming round timeout")
		rtState.Timer.Stop(ctx)
	} else {
		// (Re-)arm timer.
		app.logger.Debug("(re-)arming round timeout")

		timerCtx := &timerContext{
			ID:    runtime.ID,
			Round: blockNr,
		}
		rtState.Timer.Reset(ctx, nextTimeout.Sub(ctx.Now()), timerCtx.MarshalCBOR())
	}
}

func (app *rootHashApplication) tryFinalizeCompute(
	ctx *abci.Context,
	runtime *registry.Runtime,
	rtState *runtimeState,
	pool *commitment.Pool,
	forced bool,
) { // nolint: gocyclo
	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round
	id, _ := runtime.ID.MarshalBinary()
	committeeID := pool.GetCommitteeID()

	defer app.updateTimer(ctx, runtime, rtState, blockNr)

	if rtState.Round.Finalized {
		app.logger.Error("attempted to finalize compute when block already finalized",
			"round", blockNr,
			"committee_id", committeeID,
		)
		return
	}

	// TODO: Separate timeout for compute/merge.
	_, err := pool.TryFinalize(ctx.Now(), app.roundTimeout, forced)
	switch err {
	case nil:
		// No error -- there is no discrepancy. But only the merge committee
		// can make progress even if we have all compute commitments.

		// TODO: Check if we need to punish the merge committee.

		app.logger.Warn("no compute discrepancy, but only merge committee can make progress",
			"round", blockNr,
			"committee_id", committeeID,
		)

		if !forced {
			// If this was not a timeout, we give the merge committee some
			// more time to merge, otherwise we fail the round.
			return
		}
	case commitment.ErrStillWaiting:
		// Need more commits.
		return
	case commitment.ErrDiscrepancyDetected:
		// Discrepancy has been detected.
		app.logger.Warn("compute discrepancy detected",
			"round", blockNr,
			"committee_id", committeeID,
		)

		ctx.EmitTag(TagUpdate, TagUpdateValue)
		tagV := ValueComputeDiscrepancyDetected{
			ID: id,
			Event: roothash.ComputeDiscrepancyDetectedEvent{
				CommitteeID: pool.GetCommitteeID(),
			},
		}
		ctx.EmitTag(TagComputeDiscrepancyDetected, tagV.MarshalCBOR())
		return
	default:
	}

	// Something else went wrong, emit empty error block. Note that we need
	// to abort everything even if only one committee failed to finalize as
	// there is otherwise no way to make progress as merge committees will
	// refuse to merge if there are discrepancies.
	app.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	app.emitEmptyBlock(ctx, rtState, block.RoundFailed)
}

func (app *rootHashApplication) tryFinalizeMerge(
	ctx *abci.Context,
	runtime *registry.Runtime,
	rtState *runtimeState,
	forced bool,
) { // nolint: gocyclo
	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round
	id, _ := runtime.ID.MarshalBinary()

	defer app.updateTimer(ctx, runtime, rtState, blockNr)

	if rtState.Round.Finalized {
		app.logger.Error("attempted to finalize merge when block already finalized",
			"round", blockNr,
		)
		return
	}

	commit, err := rtState.Round.MergePool.TryFinalize(ctx.Now(), app.roundTimeout, forced)
	switch err {
	case nil:
		// Round has been finalized.
		app.logger.Debug("finalized round",
			"round", blockNr,
		)

		// Generate the final block.
		blk := new(block.Block)
		blk.Header = commit.ToDDResult().(block.Header)
		blk.Header.Timestamp = uint64(ctx.Now().Unix())

		rtState.Round.MergePool.ResetCommitments()
		rtState.Round.ComputePool.ResetCommitments()
		rtState.Round.Finalized = true
		rtState.CurrentBlock = blk

		ctx.EmitTag(TagUpdate, TagUpdateValue)
		tagV := ValueFinalized{
			ID:    id,
			Round: blk.Header.Round,
		}
		ctx.EmitTag(TagFinalized, tagV.MarshalCBOR())
		return
	case commitment.ErrStillWaiting:
		// Need more commits.
		app.logger.Debug("insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		return
	case commitment.ErrDiscrepancyDetected:
		// Discrepancy has been detected.
		app.logger.Warn("merge discrepancy detected",
			"round", blockNr,
		)

		ctx.EmitTag(TagUpdate, TagUpdateValue)
		tagV := ValueMergeDiscrepancyDetected{
			ID:    id,
			Event: roothash.MergeDiscrepancyDetectedEvent{},
		}
		ctx.EmitTag(TagMergeDiscrepancyDetected, tagV.MarshalCBOR())
		return
	default:
	}

	// Something else went wrong, emit empty error block.
	app.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	app.emitEmptyBlock(ctx, rtState, block.RoundFailed)
}

// New constructs a new roothash application instance.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	beacon beacon.Backend,
	roundTimeout time.Duration,
) abci.Application {
	return &rootHashApplication{
		ctx:          ctx,
		logger:       logging.GetLogger("tendermint/roothash"),
		timeSource:   timeSource,
		beacon:       beacon,
		roundTimeout: roundTimeout,
	}
}
