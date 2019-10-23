// Package roothash implements the roothash application.
package roothash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	registryapp "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	registryState "github.com/oasislabs/oasis-core/go/tendermint/apps/registry/state"
	roothashState "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash/state"
	schedulerapp "github.com/oasislabs/oasis-core/go/tendermint/apps/scheduler"
	schedulerState "github.com/oasislabs/oasis-core/go/tendermint/apps/scheduler/state"
	stakingapp "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
)

// timerKindRound is the round timer kind.
const timerKindRound = 0x01

var (
	errNoSuchRuntime = errors.New("tendermint/roothash: no such runtime")
	errNoRound       = errors.New("tendermint/roothash: no round in progress")

	_ abci.Application = (*rootHashApplication)(nil)
)

type timerContext struct {
	ID    signature.PublicKey `json:"id"`
	Round uint64              `json:"round"`
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

func (app *rootHashApplication) Dependencies() []string {
	return []string{schedulerapp.AppName, stakingapp.AppName}
}

func (app *rootHashApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *rootHashApplication) OnCleanup() {
}

func (app *rootHashApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.RootHash

	// Store initial round timeout from the genesis document.
	rhState := roothashState.NewMutableState(ctx.State())
	rhState.SetRoundTimeout(st.RoundTimeout)

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes()
	for _, v := range runtimes {
		app.logger.Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		app.onNewRuntime(ctx, v, &st)
	}

	return nil
}

func (app *rootHashApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// Check if rescheduling has taken place.
	rescheduled := ctx.HasEvent(schedulerapp.AppName, schedulerapp.KeyElected)
	// Check if there was an epoch transition.
	epochChanged, epoch := app.state.EpochChanged(ctx, app.timeSource)

	if epochChanged || rescheduled {
		return app.onCommitteeChanged(ctx, epoch)
	}
	return nil
}

func (app *rootHashApplication) onCommitteeChanged(ctx *abci.Context, epoch epochtime.EpochTime) error { // nolint: gocyclo
	state := roothashState.NewMutableState(ctx.State())

	// Query the updated runtime list.
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes()
	newDescriptors := make(map[signature.MapKey]*registry.Runtime)
	for _, v := range runtimes {
		if v.Kind == registry.KindCompute {
			newDescriptors[v.ID.ToMapKey()] = v
		}
	}

	schedState := schedulerState.NewMutableState(ctx.State())
	for _, rtState := range state.Runtimes() {
		rtID := rtState.Runtime.ID

		if !rtState.Runtime.IsCompute() {
			app.logger.Debug("checkCommittees: skipping non-compute runtime",
				"runtime", rtID,
			)
			continue
		}

		// Derive a deterministic committee identifier that depends on memberships
		// of all committees. We need this to be able to quickly see if any
		// committee members have changed.
		//
		// We first include the current epoch, then all compute committee member
		// hashes and then the merge committee member hash:
		//
		//   [little-endian epoch]
		//   "compute committees follow"
		//   [compute committe 1 members hash]
		//   [compute committe 2 members hash]
		//   ...
		//   [compute committe n members hash]
		//   "merge committee follows"
		//   [merge committee members hash]
		//
		var committeeIDParts [][]byte
		var rawEpoch [8]byte
		binary.LittleEndian.PutUint64(rawEpoch[:], uint64(epoch))
		committeeIDParts = append(committeeIDParts, rawEpoch[:])
		committeeIDParts = append(committeeIDParts, []byte("compute committees follow"))

		// NOTE: There will later be multiple compute committees.
		var computeCommittees []*scheduler.Committee
		cc1, err := schedState.Committee(scheduler.KindCompute, rtID)
		if err != nil {
			app.logger.Error("checkCommittees: failed to get compute committee from scheduler",
				"err", err,
				"runtime", rtID,
			)
			continue
		}
		if cc1 != nil {
			computeCommittees = append(computeCommittees, cc1)
		}

		computePool := &commitment.MultiPool{
			Committees: make(map[hash.Hash]*commitment.Pool),
		}
		if len(computeCommittees) == 0 {
			app.logger.Warn("checkCommittees: no compute committees",
				"runtime", rtID,
			)
		}
		for _, computeCommittee := range computeCommittees {
			computeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
			for idx, n := range computeCommittee.Members {
				var nodeRuntime *node.Runtime
				node, err1 := regState.Node(n.PublicKey)
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
			computeCommitteeID := computeCommittee.EncodedMembersHash()
			committeeIDParts = append(committeeIDParts, computeCommitteeID[:])

			computePool.Committees[computeCommitteeID] = &commitment.Pool{
				Runtime:   rtState.Runtime,
				Committee: computeCommittee,
				NodeInfo:  computeNodeInfo,
			}
		}

		var mergePool commitment.Pool
		committeeIDParts = append(committeeIDParts, []byte("merge committee follows"))
		mergeCommittee, err := schedState.Committee(scheduler.KindMerge, rtID)
		if err != nil {
			app.logger.Error("checkCommittees: failed to get merge committee from scheduler",
				"err", err,
				"runtime", rtID,
			)
			continue
		}
		if mergeCommittee == nil {
			app.logger.Warn("checkCommittees: no merge committee",
				"runtime", rtID,
			)
		} else {
			mergeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
			for idx, n := range mergeCommittee.Members {
				mergeNodeInfo[n.PublicKey.ToMapKey()] = commitment.NodeInfo{
					CommitteeNode: idx,
				}
			}
			mergePool = commitment.Pool{
				Runtime:   rtState.Runtime,
				Committee: mergeCommittee,
				NodeInfo:  mergeNodeInfo,
			}
			mergeCommitteeID := mergeCommittee.EncodedMembersHash()
			committeeIDParts = append(committeeIDParts, mergeCommitteeID[:])
		}

		app.logger.Debug("checkCommittees: updating committee for runtime",
			"runtime", rtID,
		)

		// If the committee is the "same", ignore this.
		var committeeID hash.Hash
		committeeID.FromBytes(committeeIDParts...)

		round := rtState.Round
		if round != nil && round.CommitteeID.Equal(&committeeID) {
			app.logger.Debug("checkCommittees: duplicate committee, ignoring",
				"runtime", rtID,
				"committee_id", committeeID,
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
			"committee_id", committeeID,
			"round", blockNr,
		)

		rtState.Timer.Stop(ctx)
		rtState.Round = roothashState.NewRound(committeeID, computePool, &mergePool, blk)

		// Emit an empty epoch transition block in the new round. This is required so that
		// the clients can be sure what state is final when an epoch transition occurs.
		app.emitEmptyBlock(ctx, rtState, block.EpochTransition)

		mk := rtID.ToMapKey()
		if rt, ok := newDescriptors[mk]; ok {
			// Update the runtime descriptor to the latest per-epoch value.
			rtState.Runtime = rt
			delete(newDescriptors, mk)
		}

		state.SetRuntimeState(rtState)
	}

	// Just because a runtime didn't have committees, it doesn't mean that
	// it's state does not need to be updated. Do so now where possible.
	for _, v := range newDescriptors {
		rtState, err := state.RuntimeState(v.ID)
		if err != nil {
			app.logger.Warn("onEpochChange: unknown runtime in update pass",
				"runtime", v,
			)
			continue
		}

		rtState.Runtime = v
		state.SetRuntimeState(rtState)
	}

	return nil
}

func (app *rootHashApplication) emitEmptyBlock(ctx *abci.Context, runtime *roothashState.RuntimeState, hdrType block.HeaderType) {
	blk := block.NewEmptyBlock(runtime.CurrentBlock, uint64(ctx.Now().Unix()), hdrType)

	runtime.Timer.Stop(ctx)
	runtime.CurrentBlock = blk

	tagV := ValueFinalized{
		ID:    runtime.Runtime.ID,
		Round: blk.Header.Round,
	}
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, tagV.MarshalCBOR()))
}

func (app *rootHashApplication) ExecuteTx(ctx *abci.Context, rawTx []byte) error {
	var tx Tx
	if err := cbor.Unmarshal(rawTx, &tx); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(rawTx),
		)
		return errors.Wrap(err, "roothash: failed to unmarshal")
	}

	state := roothashState.NewMutableState(ctx.State())

	if tx.TxMergeCommit != nil {
		return app.commit(ctx, state, tx.TxMergeCommit.ID, &tx)
	} else if tx.TxComputeCommit != nil {
		return app.commit(ctx, state, tx.TxComputeCommit.ID, &tx)
	}
	return roothash.ErrInvalidArgument
}

func (app *rootHashApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx []byte) error {
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

					app.logger.Debug("ForeignDeliverTx: new runtime",
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
		app.logger.Warn("onNewRuntime: ignoring non-compute runtime",
			"runtime", runtime,
		)
		return
	}

	// Check if state already exists for the given runtime.
	rtState, _ := state.RuntimeState(runtime.ID)
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
	state.SetRuntimeState(&roothashState.RuntimeState{
		Runtime:      runtime,
		CurrentBlock: genesisBlock,
		GenesisBlock: genesisBlock,
		Timer:        *abci.NewTimer(ctx, app, timerKindRound, runtime.ID[:], timerCtx.MarshalCBOR()),
	})

	app.logger.Debug("onNewRuntime: created genesis state for runtime",
		"runtime", runtime,
	)

	// This transaction now also includes a new block for the given runtime.
	id, _ := runtime.ID.MarshalBinary()
	tagV := ValueFinalized{
		ID:    id,
		Round: genesisBlock.Header.Round,
	}
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, tagV.MarshalCBOR()))
}

func (app *rootHashApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *rootHashApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	if timer.Kind() != timerKindRound {
		return errors.New("tendermint/roothash: unexpected timer")
	}

	var tCtx timerContext
	if err := tCtx.UnmarshalCBOR(timer.Data(ctx)); err != nil {
		return err
	}

	app.logger.Warn("FireTimer: timer fired",
		logging.LogEvent, roothash.LogEventTimerFired,
	)

	state := roothashState.NewMutableState(ctx.State())
	rtState, err := state.RuntimeState(tCtx.ID)
	if err != nil {
		app.logger.Error("FireTimer: failed to get state associated with timer",
			"err", err,
		)
		return err
	}
	runtime := rtState.Runtime

	latestBlock := rtState.CurrentBlock
	if latestBlock.Header.Round != tCtx.Round {
		// Note: This should NEVER happen.
		app.logger.Error("FireTimer: spurious timeout detected",
			"runtime", tCtx.ID,
			"timer_round", tCtx.Round,
			"current_round", latestBlock.Header.Round,
		)

		timer.Stop(ctx)

		return errors.New("tendermint/roothash: spurious timeout")
	}

	app.logger.Warn("FireTimer: round timeout expired, forcing finalization",
		"runtime", tCtx.ID,
		"timer_round", tCtx.Round,
	)

	defer state.SetRuntimeState(rtState)

	if rtState.Round.MergePool.IsTimeout(ctx.Now()) {
		if err := app.tryFinalizeBlock(ctx, runtime, rtState, true); err != nil {
			app.logger.Error("failed to finalize block",
				"err", err,
			)
			panic(err)
		}
	}
	for _, pool := range rtState.Round.ComputePool.GetTimeoutCommittees(ctx.Now()) {
		app.tryFinalizeCompute(ctx, runtime, rtState, pool, true)
	}

	return nil
}

type roothashSignatureVerifier struct {
	runtimeID signature.PublicKey
	scheduler *schedulerState.MutableState
}

// VerifyCommitteeSignatures verifies that the given signatures come from
// the current committee members of the given kind.
//
// Implements commitment.SignatureVerifier.
func (sv *roothashSignatureVerifier) VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error {
	if len(sigs) == 0 {
		return nil
	}

	committee, err := sv.scheduler.Committee(kind, sv.runtimeID)
	if err != nil {
		return err
	}
	if committee == nil {
		return errors.New("roothash: no committee with which to verify signatures")
	}

	// TODO: Consider caching this set?
	pks := make(map[signature.MapKey]bool)
	for _, m := range committee.Members {
		pks[m.PublicKey.ToMapKey()] = true
	}

	for _, sig := range sigs {
		if !pks[sig.PublicKey.ToMapKey()] {
			return errors.New("roothash: signature is not from a valid committee member")
		}
	}
	return nil
}

func (app *rootHashApplication) commit(
	ctx *abci.Context,
	state *roothashState.MutableState,
	id signature.PublicKey,
	tx *Tx,
) error {
	logger := app.logger.With("is_check_only", ctx.IsCheckOnly())

	rtState, err := state.RuntimeState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime state")
	}
	if rtState == nil {
		return errNoSuchRuntime
	}
	runtime := rtState.Runtime

	if rtState.Round == nil {
		logger.Error("commit recevied when no round in progress")
		return errNoRound
	}

	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round

	defer state.SetRuntimeState(rtState)

	// If the round was finalized, transition.
	if rtState.Round.CurrentBlock.Header.Round != latestBlock.Header.Round {
		logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		rtState.Round.Transition(latestBlock)
	}

	// Create storage signature verifier.
	sv := &roothashSignatureVerifier{
		runtimeID: id,
		scheduler: schedulerState.NewMutableState(ctx.State()),
	}

	// Add the commitments.
	switch {
	case tx.TxMergeCommit != nil:
		for _, commit := range tx.TxMergeCommit.Commits {
			if err = rtState.Round.AddMergeCommitment(&commit, sv); err != nil {
				logger.Error("failed to add merge commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}
		}

		// Try to finalize round.
		if !ctx.IsCheckOnly() {
			if err = app.tryFinalizeBlock(ctx, runtime, rtState, false); err != nil {
				logger.Error("failed to finalize block",
					"err", err,
				)
				return err
			}
		}
	case tx.TxComputeCommit != nil:
		pools := make(map[*commitment.Pool]bool)
		for _, commit := range tx.TxComputeCommit.Commits {
			var pool *commitment.Pool
			if pool, err = rtState.Round.AddComputeCommitment(&commit, sv); err != nil {
				logger.Error("failed to add compute commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}

			pools[pool] = true
		}

		// Try to finalize compute rounds.
		if !ctx.IsCheckOnly() {
			for pool := range pools {
				app.tryFinalizeCompute(ctx, runtime, rtState, pool, false)
			}
		}
	default:
		return roothash.ErrInvalidArgument
	}

	return nil
}

func (app *rootHashApplication) updateTimer(
	ctx *abci.Context,
	runtime *registry.Runtime,
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
	rtState *roothashState.RuntimeState,
	pool *commitment.Pool,
	forced bool,
) {
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
	_, err := pool.TryFinalize(ctx.Now(), app.roundTimeout, forced, true)
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
			logging.LogEvent, roothash.LogEventComputeDiscrepancyDetected,
		)

		tagV := ValueComputeDiscrepancyDetected{
			ID: id,
			Event: roothash.ComputeDiscrepancyDetectedEvent{
				CommitteeID: pool.GetCommitteeID(),
				Timeout:     forced,
			},
		}
		ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyComputeDiscrepancyDetected, tagV.MarshalCBOR()))
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
		logging.LogEvent, roothash.LogEventRoundFailed,
	)

	app.emitEmptyBlock(ctx, rtState, block.RoundFailed)
}

func (app *rootHashApplication) tryFinalizeMerge(
	ctx *abci.Context,
	runtime *registry.Runtime,
	rtState *roothashState.RuntimeState,
	forced bool,
) *block.Block {
	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round
	id, _ := runtime.ID.MarshalBinary()

	defer app.updateTimer(ctx, runtime, rtState, blockNr)

	if rtState.Round.Finalized {
		app.logger.Error("attempted to finalize merge when block already finalized",
			"round", blockNr,
		)
		return nil
	}

	commit, err := rtState.Round.MergePool.TryFinalize(ctx.Now(), app.roundTimeout, forced, true)
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

		return blk
	case commitment.ErrStillWaiting:
		// Need more commits.
		app.logger.Debug("insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		return nil
	case commitment.ErrDiscrepancyDetected:
		// Discrepancy has been detected.
		app.logger.Warn("merge discrepancy detected",
			"round", blockNr,
			logging.LogEvent, roothash.LogEventMergeDiscrepancyDetected,
		)

		tagV := ValueMergeDiscrepancyDetected{
			ID:    id,
			Event: roothash.MergeDiscrepancyDetectedEvent{},
		}
		ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyMergeDiscrepancyDetected, tagV.MarshalCBOR()))
		return nil
	default:
	}

	// Something else went wrong, emit empty error block.
	app.logger.Error("worker: round failed",
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

	for _, message := range blk.Header.RoothashMessages {
		// Check with staking.
		stakingState := stakingState.NewMutableState(ctx.State())
		unsat, err := stakingState.HandleRoothashMessage(rtState.Runtime.ID, message)
		if err != nil {
			return err
		}
		if unsat != nil {
			app.logger.Error("staking not satisfied with roothash message",
				"roothash_message", message,
				"err", unsat,
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
	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyFinalized, tagV.MarshalCBOR()))

	return nil
}

func (app *rootHashApplication) tryFinalizeBlock(
	ctx *abci.Context,
	runtime *registry.Runtime,
	rtState *roothashState.RuntimeState,
	mergeForced bool,
) error {
	finalizedBlock := app.tryFinalizeMerge(ctx, runtime, rtState, mergeForced)
	if finalizedBlock == nil {
		return nil
	}

	if err := app.postProcessFinalizedBlock(ctx, rtState, finalizedBlock); err != nil {
		return err
	}

	return nil
}

// New constructs a new roothash application instance.
func New(
	timeSource epochtime.Backend,
	beacon beacon.Backend,
	roundTimeout time.Duration,
) abci.Application {
	return &rootHashApplication{
		logger:       logging.GetLogger("tendermint/roothash"),
		timeSource:   timeSource,
		beacon:       beacon,
		roundTimeout: roundTimeout,
	}
}
