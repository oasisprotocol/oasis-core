// Package roothash implements the roothash application.
package roothash

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	tmapi "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	registryapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler"
	schedulerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

// timerKindRound is the round timer kind.
const timerKindRound = 0x01

var _ abci.Application = (*rootHashApplication)(nil)

type timerContext struct {
	ID    common.Namespace `json:"id"`
	Round uint64           `json:"round"`
}

type rootHashApplication struct {
	state abci.ApplicationState

	beacon beacon.Backend
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

func (app *rootHashApplication) OnRegister(state abci.ApplicationState) {
	app.state = state
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// Check if rescheduling has taken place.
	rescheduled := ctx.HasEvent(schedulerapp.AppName, schedulerapp.KeyElected)
	// Check if there was an epoch transition.
	epochChanged, epoch := app.state.EpochChanged(ctx)

	if epochChanged || rescheduled {
		return app.onCommitteeChanged(ctx, epoch)
	}
	return nil
}

func (app *rootHashApplication) onCommitteeChanged(ctx *abci.Context, epoch epochtime.EpochTime) error {
	state := roothashState.NewMutableState(ctx.State())
	schedState := schedulerState.NewMutableState(ctx.State())
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes()

	params, err := state.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}

	for _, rt := range runtimes {
		if !rt.IsCompute() {
			ctx.Logger().Debug("skipping non-compute runtime",
				"runtime", rt.ID,
			)
			continue
		}

		rtState, err := state.RuntimeState(rt.ID)
		if err != nil {
			return fmt.Errorf("failed to fetch runtime state: %w", err)
		}

		// Since the runtime is in the list of active runtimes in the registry we
		// can safely clear the suspended flag.
		rtState.Suspended = false

		// Prepare new runtime committees based on what the scheduler did.
		committeeID, executorPool, mergePool, empty, err := app.prepareNewCommittees(ctx, epoch, rtState, schedState, regState)
		if err != nil {
			return err
		}

		// If there are no committees for this runtime, suspend the runtime as this
		// means that there is noone to pay the maintenance fees.
		if empty && !params.DebugDoNotSuspendRuntimes {
			if err := app.suspendUnpaidRuntime(ctx, rtState, regState); err != nil {
				return err
			}
		}

		// If the committee has actually changed, force a new round.
		if !rtState.Suspended && (rtState.Round == nil || !rtState.Round.CommitteeID.Equal(&committeeID)) {
			ctx.Logger().Debug("updating committee for runtime",
				"runtime_id", rt.ID,
			)

			// Transition the round.
			blk := rtState.CurrentBlock
			blockNr := blk.Header.Round

			ctx.Logger().Debug("new committee, transitioning round",
				"runtime_id", rt.ID,
				"committee_id", committeeID,
				"round", blockNr,
			)

			// Emit an empty epoch transition block in the new round. This is required so that
			// the clients can be sure what state is final when an epoch transition occurs.
			app.emitEmptyBlock(ctx, rtState, block.EpochTransition)

			// Create a new round.
			rtState.Round = roothashState.NewRound(committeeID, executorPool, mergePool, rtState.CurrentBlock)
		}

		// Update the runtime descriptor to the latest per-epoch value.
		rtState.Runtime = rt

		state.SetRuntimeState(rtState)
	}

	return nil
}

func (app *rootHashApplication) suspendUnpaidRuntime(
	ctx *abci.Context,
	rtState *roothashState.RuntimeState,
	regState *registryState.MutableState,
) error {
	ctx.Logger().Warn("maintenance fees not paid for runtime, suspending",
		"runtime_id", rtState.Runtime.ID,
	)

	if err := regState.SuspendRuntime(rtState.Runtime.ID); err != nil {
		return err
	}

	rtState.Suspended = true
	rtState.Round = nil

	// Emity an empty block signalling that the runtime was suspended.
	app.emitEmptyBlock(ctx, rtState, block.Suspended)

	return nil
}

func (app *rootHashApplication) prepareNewCommittees(
	ctx *abci.Context,
	epoch epochtime.EpochTime,
	rtState *roothashState.RuntimeState,
	schedState *schedulerState.MutableState,
	regState *registryState.MutableState,
) (
	committeeID hash.Hash,
	executorPool *commitment.MultiPool,
	mergePool *commitment.Pool,
	empty bool,
	err error,
) {
	rtID := rtState.Runtime.ID

	// Derive a deterministic committee identifier that depends on memberships
	// of all committees. We need this to be able to quickly see if any
	// committee members have changed.
	//
	// We first include the current epoch, then all executor committee member
	// hashes and then the merge committee member hash:
	//
	//   [little-endian epoch]
	//   "executor committees follow"
	//   [executor committe 1 members hash]
	//   [executor committe 2 members hash]
	//   ...
	//   [executor committe n members hash]
	//   "merge committee follows"
	//   [merge committee members hash]
	//
	var committeeIDParts [][]byte
	var rawEpoch [8]byte
	binary.LittleEndian.PutUint64(rawEpoch[:], uint64(epoch))
	committeeIDParts = append(committeeIDParts, rawEpoch[:])
	committeeIDParts = append(committeeIDParts, []byte("executor committees follow"))

	// NOTE: There will later be multiple executor committees.
	var executorCommittees []*scheduler.Committee
	xc1, err := schedState.Committee(scheduler.KindComputeExecutor, rtID)
	if err != nil {
		ctx.Logger().Error("checkCommittees: failed to get executor committee from scheduler",
			"err", err,
			"runtime", rtID,
		)
		return
	}
	if xc1 != nil {
		executorCommittees = append(executorCommittees, xc1)
	}

	executorPool = &commitment.MultiPool{
		Committees: make(map[hash.Hash]*commitment.Pool),
	}
	if len(executorCommittees) == 0 {
		ctx.Logger().Warn("checkCommittees: no executor committees",
			"runtime", rtID,
		)
		empty = true
	}
	for _, executorCommittee := range executorCommittees {
		executorCommitteeID := executorCommittee.EncodedMembersHash()
		committeeIDParts = append(committeeIDParts, executorCommitteeID[:])

		executorPool.Committees[executorCommitteeID] = &commitment.Pool{
			Runtime:   rtState.Runtime,
			Committee: executorCommittee,
		}
	}

	mergePool = new(commitment.Pool)
	committeeIDParts = append(committeeIDParts, []byte("merge committee follows"))
	mergeCommittee, err := schedState.Committee(scheduler.KindComputeMerge, rtID)
	if err != nil {
		ctx.Logger().Error("checkCommittees: failed to get merge committee from scheduler",
			"err", err,
			"runtime", rtID,
		)
		return
	}
	if mergeCommittee == nil {
		ctx.Logger().Warn("checkCommittees: no merge committee",
			"runtime", rtID,
		)
		empty = true
	} else {
		mergePool = &commitment.Pool{
			Runtime:   rtState.Runtime,
			Committee: mergeCommittee,
		}
		mergeCommitteeID := mergeCommittee.EncodedMembersHash()
		committeeIDParts = append(committeeIDParts, mergeCommitteeID[:])
	}

	committeeID.FromBytes(committeeIDParts...)
	return
}

func (app *rootHashApplication) emitEmptyBlock(ctx *abci.Context, runtime *roothashState.RuntimeState, hdrType block.HeaderType) {
	blk := block.NewEmptyBlock(runtime.CurrentBlock, uint64(ctx.Now().Unix()), hdrType)

	runtime.Timer.Stop(ctx)
	runtime.CurrentBlock = blk

	tagV := ValueFinalized{
		ID:    runtime.Runtime.ID,
		Round: blk.Header.Round,
	}
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, cbor.Marshal(tagV)))
}

func (app *rootHashApplication) ExecuteTx(ctx *abci.Context, tx *transaction.Transaction) error {
	state := roothashState.NewMutableState(ctx.State())

	switch tx.Method {
	case roothash.MethodExecutorCommit:
		var xc roothash.ExecutorCommit
		if err := cbor.Unmarshal(tx.Body, &xc); err != nil {
			return err
		}

		return app.executorCommit(ctx, state, &xc)
	case roothash.MethodMergeCommit:
		var mc roothash.MergeCommit
		if err := cbor.Unmarshal(tx.Body, &mc); err != nil {
			return err
		}

		return app.mergeCommit(ctx, state, &mc)
	default:
		return roothash.ErrInvalidArgument
	}
}

func (app *rootHashApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	var st *roothash.Genesis
	ensureGenesis := func() {
		st = &app.state.Genesis().RootHash
	}

	switch other.Name() {
	case registryapp.AppName:
		for _, ev := range ctx.GetEvents() {
			if ev.Type != registryapp.EventType {
				continue
			}

			for _, pair := range ev.Attributes {
				if bytes.Equal(pair.GetKey(), registryapp.KeyRuntimeRegistered) {
					var rt registry.Runtime
					if err := cbor.Unmarshal(pair.GetValue(), &rt); err != nil {
						return errors.Wrap(err, "roothash: failed to deserialize new runtime")
					}

					ctx.Logger().Debug("ForeignDeliverTx: new runtime",
						"runtime", rt.ID,
					)

					ensureGenesis()
					app.onNewRuntime(ctx, &rt, st)
				}
			}
		}
	}

	return nil
}

func (app *rootHashApplication) onNewRuntime(ctx *abci.Context, runtime *registry.Runtime, genesis *roothash.Genesis) {
	state := roothashState.NewMutableState(ctx.State())

	if !runtime.IsCompute() {
		ctx.Logger().Warn("onNewRuntime: ignoring non-compute runtime",
			"runtime", runtime,
		)
		return
	}

	// Check if state already exists for the given runtime.
	if _, err := state.RuntimeState(runtime.ID); err != roothash.ErrInvalidRuntime {
		ctx.Logger().Warn("onNewRuntime: state for runtime already exists",
			"runtime", runtime,
		)
		return
	}

	// Create genesis block.
	now := ctx.Now().Unix()
	genesisBlock := block.NewGenesisBlock(runtime.ID, uint64(now))
	// Fill the Header fields with Genesis runtime states, if this was called during InitChain().
	genesisBlock.Header.Round = runtime.Genesis.Round
	genesisBlock.Header.StateRoot = runtime.Genesis.StateRoot
	genesisBlock.Header.StorageSignatures = runtime.Genesis.StorageReceipts
	if ctx.IsInitChain() {
		genesisRts := genesis.RuntimeStates[runtime.ID]
		if genesisRts != nil {
			genesisBlock.Header.Round = genesisRts.Round
			genesisBlock.Header.StateRoot = genesisRts.StateRoot
			genesisBlock.Header.StorageSignatures = runtime.Genesis.StorageReceipts
		}
	}

	// Create new state containing the genesis block.
	timerCtx := &timerContext{ID: runtime.ID}
	state.SetRuntimeState(&roothashState.RuntimeState{
		Runtime:      runtime,
		CurrentBlock: genesisBlock,
		GenesisBlock: genesisBlock,
		Timer:        *abci.NewTimer(ctx, app, timerKindRound, runtime.ID[:], cbor.Marshal(timerCtx)),
	})

	ctx.Logger().Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	// This transaction now also includes a new block for the given runtime.
	tagV := ValueFinalized{
		ID:    runtime.ID,
		Round: genesisBlock.Header.Round,
	}
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, cbor.Marshal(tagV)))
}

func (app *rootHashApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *rootHashApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	if timer.Kind() != timerKindRound {
		return errors.New("tendermint/roothash: unexpected timer")
	}

	var tCtx timerContext
	if err := cbor.Unmarshal(timer.Data(ctx), &tCtx); err != nil {
		return err
	}

	ctx.Logger().Warn("FireTimer: timer fired",
		logging.LogEvent, roothash.LogEventTimerFired,
	)

	state := roothashState.NewMutableState(ctx.State())
	rtState, err := state.RuntimeState(tCtx.ID)
	if err != nil {
		ctx.Logger().Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		return err
	}

	latestBlock := rtState.CurrentBlock
	if latestBlock.Header.Round != tCtx.Round {
		// Note: This should NEVER happen.
		ctx.Logger().Error("FireTimer: spurious timeout detected",
			"runtime", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", latestBlock.Header.Round,
		)

		timer.Stop(ctx)

		return errors.New("tendermint/roothash: spurious timeout")
	}

	ctx.Logger().Warn("FireTimer: round timeout expired, forcing finalization",
		"runtime", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.SetRuntimeState(rtState)

	if rtState.Round.MergePool.IsTimeout(ctx.Now()) {
		if err := app.tryFinalizeBlock(ctx, rtState, true); err != nil {
			ctx.Logger().Error("failed to finalize block",
				"err", err,
			)
			panic(err)
		}
	}
	for _, pool := range rtState.Round.ExecutorPool.GetTimeoutCommittees(ctx.Now()) {
		app.tryFinalizeExecute(ctx, rtState, pool, true)
	}

	return nil
}

func (app *rootHashApplication) updateTimer(
	ctx *abci.Context,
	rtState *roothashState.RuntimeState,
	blockNr uint64,
) {
	// Do not re-arm the timer if the round has already changed.
	if blockNr != rtState.CurrentBlock.Header.Round {
		return
	}

	nextTimeout := rtState.Round.GetNextTimeout()
	if nextTimeout.IsZero() {
		// Disarm timer.
		ctx.Logger().Debug("disarming round timeout")
		rtState.Timer.Stop(ctx)
	} else {
		// (Re-)arm timer.
		ctx.Logger().Debug("(re-)arming round timeout")

		timerCtx := &timerContext{
			ID:    rtState.Runtime.ID,
			Round: blockNr,
		}
		rtState.Timer.Reset(ctx, nextTimeout.Sub(ctx.Now()), cbor.Marshal(timerCtx))
	}
}

func (app *rootHashApplication) tryFinalizeExecute(
	ctx *abci.Context,
	rtState *roothashState.RuntimeState,
	pool *commitment.Pool,
	forced bool,
) {
	runtime := rtState.Runtime
	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round
	committeeID := pool.GetCommitteeID()

	defer app.updateTimer(ctx, rtState, blockNr)

	if rtState.Round.Finalized {
		ctx.Logger().Error("attempted to finalize execute when block already finalized",
			"round", blockNr,
			"committee_id", committeeID,
		)
		return
	}

	_, err := pool.TryFinalize(ctx.Now(), runtime.Executor.RoundTimeout, forced, true)
	switch err {
	case nil:
		// No error -- there is no discrepancy. But only the merge committee
		// can make progress even if we have all executor commitments.

		// TODO: Check if we need to punish the merge committee.

		ctx.Logger().Warn("no execution discrepancy, but only merge committee can make progress",
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
		ctx.Logger().Warn("execution discrepancy detected",
			"round", blockNr,
			"committee_id", committeeID,
			logging.LogEvent, roothash.LogEventExecutionDiscrepancyDetected,
		)

		tagV := ValueExecutionDiscrepancyDetected{
			ID: runtime.ID,
			Event: roothash.ExecutionDiscrepancyDetectedEvent{
				CommitteeID: pool.GetCommitteeID(),
				Timeout:     forced,
			},
		}
		ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyExecutionDiscrepancyDetected, cbor.Marshal(tagV)))
		return
	default:
	}

	// Something else went wrong, emit empty error block. Note that we need
	// to abort everything even if only one committee failed to finalize as
	// there is otherwise no way to make progress as merge committees will
	// refuse to merge if there are discrepancies.
	ctx.Logger().Error("round failed",
		"round", blockNr,
		"err", err,
		logging.LogEvent, roothash.LogEventRoundFailed,
	)

	app.emitEmptyBlock(ctx, rtState, block.RoundFailed)
}

func (app *rootHashApplication) tryFinalizeMerge(
	ctx *abci.Context,
	rtState *roothashState.RuntimeState,
	forced bool,
) *block.Block {
	runtime := rtState.Runtime
	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round

	defer app.updateTimer(ctx, rtState, blockNr)

	if rtState.Round.Finalized {
		ctx.Logger().Error("attempted to finalize merge when block already finalized",
			"round", blockNr,
		)
		return nil
	}

	commit, err := rtState.Round.MergePool.TryFinalize(ctx.Now(), runtime.Merge.RoundTimeout, forced, true)
	switch err {
	case nil:
		// Round has been finalized.
		ctx.Logger().Debug("finalized round",
			"round", blockNr,
		)

		// Generate the final block.
		blk := new(block.Block)
		blk.Header = commit.ToDDResult().(block.Header)
		blk.Header.Timestamp = uint64(ctx.Now().Unix())

		rtState.Round.MergePool.ResetCommitments()
		rtState.Round.ExecutorPool.ResetCommitments()
		rtState.Round.Finalized = true

		return blk
	case commitment.ErrStillWaiting:
		// Need more commits.
		ctx.Logger().Debug("insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		return nil
	case commitment.ErrDiscrepancyDetected:
		// Discrepancy has been detected.
		ctx.Logger().Warn("merge discrepancy detected",
			"round", blockNr,
			logging.LogEvent, roothash.LogEventMergeDiscrepancyDetected,
		)

		tagV := ValueMergeDiscrepancyDetected{
			ID:    runtime.ID,
			Event: roothash.MergeDiscrepancyDetectedEvent{},
		}
		ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyMergeDiscrepancyDetected, cbor.Marshal(tagV)))
		return nil
	default:
	}

	// Something else went wrong, emit empty error block.
	ctx.Logger().Error("round failed",
		"round", blockNr,
		"err", err,
		logging.LogEvent, roothash.LogEventRoundFailed,
	)

	app.emitEmptyBlock(ctx, rtState, block.RoundFailed)
	return nil
}

func (app *rootHashApplication) postProcessFinalizedBlock(ctx *abci.Context, rtState *roothashState.RuntimeState, blk *block.Block) error {
	checkpoint := ctx.NewStateCheckpoint()
	defer checkpoint.Close()

	for _, message := range blk.Header.Messages {
		// Currently there are no valid roothash messages, so any message
		// is treated as unsatisfactory. This is the place which would
		// otherwise contain message handlers.
		unsat := errors.New("tendermint/roothash: message is invalid")

		if unsat != nil {
			ctx.Logger().Error("handler not satisfied with message",
				"err", unsat,
				"message", message,
				logging.LogEvent, roothash.LogEventMessageUnsat,
			)

			// Roll back changes from message handling.
			checkpoint.Rollback()

			// Substitute empty block.
			app.emitEmptyBlock(ctx, rtState, block.RoundFailed)

			return nil
		}
	}

	// All good. Hook up the new block.
	rtState.Timer.Stop(ctx)
	rtState.CurrentBlock = blk

	tagV := ValueFinalized{
		ID:    rtState.Runtime.ID,
		Round: blk.Header.Round,
	}
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, cbor.Marshal(tagV)))

	return nil
}

func (app *rootHashApplication) tryFinalizeBlock(
	ctx *abci.Context,
	rtState *roothashState.RuntimeState,
	mergeForced bool,
) error {
	finalizedBlock := app.tryFinalizeMerge(ctx, rtState, mergeForced)
	if finalizedBlock == nil {
		return nil
	}

	if err := app.postProcessFinalizedBlock(ctx, rtState, finalizedBlock); err != nil {
		return err
	}

	return nil
}

// New constructs a new roothash application instance.
func New(beacon beacon.Backend) abci.Application {
	return &rootHashApplication{
		beacon: beacon,
	}
}
