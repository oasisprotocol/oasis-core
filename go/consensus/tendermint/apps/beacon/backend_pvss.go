package beacon

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/pvss"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	// KeyDisableRuntimes is the ABCI event attribute for signaling
	// that runtimes should be disabled due to beacon failure.
	KeyDisableRuntimes = []byte("disable_runtimes")

	validatorEntropyCtx = []byte("EkB-validator")
)

// beaconTransactionIncludedKey is the block context key for storing the beacon transaction
// inclusion flag to make sure that only a single beacon transaction is included.
type beaconTransactionIncludedKey struct{}

func (bti beaconTransactionIncludedKey) NewDefault() interface{} {
	return false
}

type backendPVSS struct {
	app *beaconApplication
}

func (impl *backendPVSS) OnInitChain(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	doc *genesis.Document,
) error {
	// If the backend is configured to use explicitly set epochs, there
	// is nothing further to do.  And yes, this ignores the base epoch,
	// but that's how certain tests are written.
	if params.DebugMockBackend {
		return nil
	}

	// Set the initial epoch.
	baseEpoch := doc.Beacon.Base
	if err := state.SetEpoch(ctx, baseEpoch, ctx.InitialHeight()); err != nil {
		return fmt.Errorf("beacon: failed to set initial epoch: %w", err)
	}

	impl.app.doEmitEpochEvent(ctx, baseEpoch)

	return nil
}

func (impl *backendPVSS) OnBeginBlock(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	req types.RequestBeginBlock,
) error {
	pvssState, err := state.PVSSState(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get PVSS state: %w", err)
	}

	future, err := state.GetFutureEpoch(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get future epoch: %w", err)
	}
	if future == nil {
		var epoch beacon.EpochTime
		if epoch, _, err = state.GetEpoch(ctx); err != nil {
			return fmt.Errorf("beacon: failed to get current epoch: %w", err)
		}

		if pvssState == nil {
			// Either this is the initial epoch, or an epoch transition
			// just happened.
			ctx.Logger().Debug("OnBeginBlock: no PVSS round pending, rearming")

			return impl.initRound(ctx, state, params, pvssState, epoch+1)
		}

		return impl.doRoundPeriodic(ctx, state, params, pvssState, epoch)
	}

	// Round finished and an epoch transition is scheduled.
	if pvssState.State != beacon.StateComplete {
		return fmt.Errorf("beacon: BUG: invalid state: %d (expected %d)", pvssState.State, beacon.StateComplete)
	}

	height := ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1
	switch {
	case future.Height < height:
		// What the fuck, we missed transitioning the epoch?
		ctx.Logger().Error("height mismatch in defered set",
			"height", height,
			"expected_height", future.Height,
		)
		return fmt.Errorf("beacon: height mismatch in defered set")
	case future.Height > height:
		// The epoch transition is scheduled to happen in the grim
		// darkness of the far future.
		return nil
	case future.Height == height:
		// Time to fire the scheduled epoch transition.
	}

	// Transition the epoch.
	ctx.Logger().Info("setting epoch",
		"epoch", future.Epoch,
		"current_height", height,
	)

	if err = state.SetEpoch(ctx, future.Epoch, height); err != nil {
		return fmt.Errorf("beacon: failed to set epoch: %w", err)
	}
	if err = state.ClearFutureEpoch(ctx); err != nil {
		return fmt.Errorf("beacon: failed to clear future epoch: %w", err)
	}
	impl.app.doEmitEpochEvent(ctx, future.Epoch)

	// Derive and broadcast the beacon.
	var b []byte
	switch params.DebugDeterministic {
	case false:
		// In the normal case, use the production context and PVSS
		// generated secure entropy.
		b = GetBeacon(future.Epoch, prodEntropyCtx, pvssState.Entropy)
	case true:
		// UNSAFE/DEBUG - Deterministic beacon.
		//
		// This is for tests only and is rigged such that the we can
		// ensure the deterministically generated node identities get
		// elected to the various committees at the appropriate times.
		//
		// See: go/oasis-test/runner/scenario/e2e/byzantine.go
		b = GetBeacon(future.Epoch, DebugEntropyCtx, DebugEntropy)
	}

	ctx.Logger().Debug("OnBeginBlock: generated beacon",
		"epoch", future.Epoch,
		"beacon", hex.EncodeToString(b),
		"pvss_entropy", hex.EncodeToString(pvssState.Entropy),
		"height", ctx.BlockHeight(),
	)

	if err = impl.app.onNewBeacon(ctx, b); err != nil {
		return fmt.Errorf("beacon: failed to set beacon: %w", err)
	}

	// Clear out the round state so that the next round is initialized
	// on the next block.  This is done so that the scheduler has an
	// opportunity to pick the next validator set.
	//
	// Note: If runtimes got killed due to prior protocol failures,
	// the upcoming epoch transition will re-enable them.
	if err = state.ClearPVSSState(ctx); err != nil {
		return fmt.Errorf("beacon: failed to clear PVSS state: %w", err)
	}

	return nil
}

func (impl *backendPVSS) doRoundPeriodic( //nolint: gocyclo
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	pvssState *beacon.PVSSState,
	epoch beacon.EpochTime,
) error {
	height := ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1

	// If the height is at the point where the epoch would have
	// transitioned assuming 0 failures, kill runtimes.
	if height == pvssState.RuntimeDisableHeight && pvssState.State != beacon.StateComplete {
		ctx.Logger().Warn("OnBeginBlock: runtime disable height reached")

		ctx.EmitEvent(api.NewEventBuilder(impl.app.Name()).Attribute(
			KeyDisableRuntimes,
			nil,
		))
	}

	// To make tests using the mock backend go faster, truncate the commit
	// and reveal periods iff every eligible node has done the right thing.
	if params.DebugMockBackend {
		var (
			delta           int64
			numParticipants = len(pvssState.Participants)
		)

		switch pvssState.State {
		case beacon.StateCommit:
			ok, totalCommits := pvssState.Instance.MayReveal()
			if ok && (totalCommits == numParticipants) {
				ctx.Logger().Debug("OnBeginBlock: accelerating reveal phase transition")

				delta = pvssState.CommitDeadline - height
				pvssState.CommitDeadline = height
				pvssState.RevealDeadline -= delta
			}
		case beacon.StateReveal:
			ok, totalReveals := pvssState.Instance.MayRecover()
			if ok && (totalReveals == numParticipants) {
				ctx.Logger().Debug("OnBeginBlock: accelerating recovery phase transition")

				delta = pvssState.RevealDeadline - height
				pvssState.RevealDeadline = height
			}
		}

		if delta > 0 {
			pvssState.RuntimeDisableHeight -= delta
			pvssState.TransitionHeight -= delta
			if err := state.SetPVSSState(ctx, pvssState); err != nil {
				return fmt.Errorf("beacon: failed to set updated PVSS state: %w", err)
			}
		}
	}

	// Round in progress.
	switch {
	case height == pvssState.CommitDeadline:
		ctx.Logger().Debug("OnBeginBlock: height is at commit deadline",
			"height", height,
		)

		if pvssState.State != beacon.StateCommit {
			return fmt.Errorf("beacon: BUG: invalid state: %d (expected %d)", pvssState.State, beacon.StateCommit)
		}

		// Persist the nodes that failed to commit.
		var failures []signature.PublicKey
		for idx, id := range pvssState.Participants {
			if pvssState.Instance.Commits[idx] == nil {
				failures = append(failures, id)
			}
		}
		impl.appendFailures(pvssState, failures)

		if ok, totalCommits := pvssState.Instance.MayReveal(); ok {
			// Update the node status to signify elgibility from the
			// next epoch.
			if err := impl.updateNodeStatus(ctx, state, epoch); err != nil {
				return fmt.Errorf("beacon: failed to update nodes snapshot: %w", err)
			}

			pvssState.Height = height
			pvssState.State = beacon.StateReveal
			if err := state.SetPVSSState(ctx, pvssState); err != nil {
				return fmt.Errorf("beacon: failed to set updated PVSS state: %w", err)
			}

			impl.doEmitPVSSEvent(ctx, pvssState)
		} else {
			// Round failed: insufficient commits.
			ctx.Logger().Error("round failed, insufficient commits",
				"total_commits", totalCommits,
			)

			return impl.initRound(ctx, state, params, pvssState, pvssState.Epoch)
		}
	case height == pvssState.RevealDeadline:
		ctx.Logger().Debug("OnBeginBlock: height is at reveal deadline",
			"height", height,
		)

		if pvssState.State != beacon.StateReveal {
			return fmt.Errorf("beacon: BUG: invalid state: %d (expected %d)", pvssState.State, beacon.StateReveal)
		}

		// Persist the nodes that failed to reveal.
		var failures []signature.PublicKey
		for idx, id := range pvssState.Participants {
			if pvssState.Instance.Reveals[idx] == nil {
				failures = append(failures, id)
			}
		}
		impl.appendFailures(pvssState, failures)

		ok, totalReveals := pvssState.Instance.MayRecover()
		if ok {
			// Recover the entropy.
			var (
				err      error
				goodIdxs []int
			)
			pvssState.Entropy, goodIdxs, err = pvssState.Instance.Recover()
			if err != nil {
				return fmt.Errorf("beacon: failed to recover entropy: %w", err)
			}

			pvssState.Height = height
			pvssState.State = beacon.StateComplete
			if err = state.SetPVSSState(ctx, pvssState); err != nil {
				return fmt.Errorf("beacon: failed to set updated PVSS state: %w", err)
			}

			goodParticipants := make(map[int]bool)
			for _, idx := range goodIdxs {
				goodParticipants[idx] = true
			}
			for idx, id := range pvssState.Participants {
				switch goodParticipants[idx] {
				case true:
					// TODO: Incentivise participation?  Should there be a
					// reward for participating in the beacon, beyond "time
					// needs to advance for various rewards to be distributed"?
				case false:
					// Slash for failing to participate fully.  A node that
					// gets BadParticipant-ed will get slashed again here
					// because there is no way for them to participate
					// fully, but that's probably ok, just don't be evil.
					//
					// Note: This currently makes no attempt to determine if
					// a node was actually able to submit the relevant tx-es.
					// It may be possible to actually attempt to mandate
					// participation, but this would likely be based on block
					// proposers and would involve a lot of extra bookkeeping.
					if err = onPVSSMisbehavior(
						ctx,
						id,
						staking.SlashBeaconNonparticipation,
					); err != nil {
						return fmt.Errorf("beacon: failed to slash for nonparticipation: %w", err)
					}
				}
			}

			impl.doEmitPVSSEvent(ctx, pvssState)

			if params.DebugMockBackend {
				ctx.Logger().Debug("round succeeded with mock backend, doing nothing")
				return nil
			}

			// Schedule the epoch transition.
			return impl.app.scheduleEpochTransitionBlock(
				ctx,
				state,
				pvssState.Epoch,
				pvssState.TransitionHeight,
			)
		}

		// Round failed: Insufficient reveals.
		ctx.Logger().Error("round failed, insufficient reveals",
			"total_reveals", totalReveals,
		)

		return impl.initRound(ctx, state, params, pvssState, pvssState.Epoch)
	default:
		if pvssState.State == beacon.StateComplete && params.DebugMockBackend {
			pendingMockEpoch, err := state.PVSSPendingMockEpoch(ctx)
			if err != nil {
				return fmt.Errorf("beacon: failed to query mock epoch state: %w", err)
			}
			if pendingMockEpoch == nil {
				// Explicit epoch set tx hasn't happened yet.
				return nil
			}

			if err = state.ClearPVSSPendingMockEpoch(ctx); err != nil {
				return fmt.Errorf("beacon: failed to clear mock epoch state: %w", err)
			}

			// Schedule the defered explicit epoch transition.
			return impl.app.scheduleEpochTransitionBlock(
				ctx,
				state,
				*pendingMockEpoch,
				height+1,
			)
		}

		// Still in either the commit or reveal period, nothing to do.
	}

	return nil
}

func (impl *backendPVSS) initRound(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	pvssState *beacon.PVSSState,
	epoch beacon.EpochTime,
) error {
	if pvssState == nil || pvssState.Epoch != epoch {
		// Yes, this obliterates the bad participant list, since nodes
		// that failed should be frozen now.
		newState := &beacon.PVSSState{
			Epoch: epoch,
		}
		pvssState = newState
	} else {
		// The previous attempt to generate a beacon for this epoch failed.
		pvssState.Round++
	}

	// Draw participants.
	entropy, err := state.Beacon(ctx)
	if err != nil && err != beacon.ErrBeaconNotAvailable {
		// Beacon not being available is "fine", the pre-sort shuffle
		// is best-effort anyway.
		return fmt.Errorf("beacon: couldn't get shuffle entropy: %w", err)
	}
	schedulerState := schedulerState.NewMutableState(ctx.State())
	registryState := registryState.NewMutableState(ctx.State())
	validators, err := schedulerState.CurrentValidators(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get current validators: %w", err)
	}

	// The byzantine test requires forcing the byzantine node to be a beacon
	// participant.
	var toForce []signature.PublicKey
	if len(params.PVSSParameters.DebugForcedParticipants) > 0 {
		forceMap := make(map[signature.PublicKey]bool)
		for _, nodeID := range params.PVSSParameters.DebugForcedParticipants {
			if forceMap[nodeID] {
				continue
			}

			var node *node.Node
			node, err = registryState.Node(ctx, nodeID)
			if err != nil {
				ctx.Logger().Error("can't force node, failed to query node descriptor",
					"id", nodeID,
					"err", err,
				)
				continue
			}

			consensusID := node.Consensus.ID
			if validators[consensusID] != 0 {
				delete(validators, consensusID)
			}

			ctx.Logger().Debug("forcing node participation in PVSS round",
				"epoch", epoch,
				"round", pvssState.Round,
				"id", nodeID,
			)

			forceMap[nodeID] = true
			toForce = append(toForce, consensusID)
		}
	}

	candidateParticipants, err := validatorsByVotingPower(validators, entropy)
	if err != nil {
		return fmt.Errorf("beacon: failed to sort current validators: %w", err)
	}
	if len(toForce) > 0 {
		candidateParticipants = append(toForce, candidateParticipants...)
	}

	numParticipants := int(params.PVSSParameters.Participants)
	participants := make([]pvss.Point, 0, numParticipants)
	participantIDs := make([]signature.PublicKey, 0, numParticipants)

	for _, validatorID := range candidateParticipants {
		if len(participants) == numParticipants {
			break
		}

		var node *node.Node
		node, err = registryState.NodeBySubKey(ctx, validatorID)
		if err != nil || node.Beacon == nil {
			continue
		}
		if pvssState.BadParticipants[node.ID] {
			continue
		}

		participants = append(participants, node.Beacon.Point)
		participantIDs = append(participantIDs, node.ID)
	}
	if l := len(participants); l < numParticipants {
		return fmt.Errorf("beacon: insufficient beacon participants: %d (want %d)", l, numParticipants)
	}

	// Initialize the PVSS state.
	if pvssState.Instance, err = pvss.New(&pvss.Config{
		Participants: participants,
		Threshold:    int(params.PVSSParameters.Threshold),
	}); err != nil {
		return fmt.Errorf("beacon: failed to initialize PVSS instance: %w", err)
	}
	pvssState.Participants = participantIDs

	// Derive the deadlines.
	//
	// Note: Because of the +1, applied to BlockHeight, it may be required
	// to strategically subtract 1 from one of the three interval/delay
	// parameters (eg: Commit/Reveal/Delay set to 20/10/4 results in
	// transitions at blocks 35, 70, 105, ...).

	height := ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1
	pvssState.CommitDeadline = height + params.PVSSParameters.CommitInterval
	pvssState.RevealDeadline = pvssState.CommitDeadline + params.PVSSParameters.RevealInterval
	pvssState.TransitionHeight = pvssState.RevealDeadline + params.PVSSParameters.TransitionDelay
	if pvssState.RuntimeDisableHeight == 0 {
		pvssState.RuntimeDisableHeight = pvssState.TransitionHeight
	}

	pvssState.Height = height
	pvssState.State = beacon.StateCommit
	if err := state.SetPVSSState(ctx, pvssState); err != nil {
		return fmt.Errorf("beacon: failed to set PVSS state: %w", err)
	}

	impl.doEmitPVSSEvent(ctx, pvssState)

	ctx.Logger().Info("initializing PVSS round",
		"epoch", epoch,
		"round", pvssState.Round,
	)

	return nil
}

func (impl *backendPVSS) ExecuteTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	tx *transaction.Transaction,
) error {
	switch tx.Method {
	case beacon.MethodPVSSReveal, beacon.MethodPVSSCommit:
		// Ensure that the tx is from the current node, to prevent blocks
		// that are loaded with gossiped beacon transactions, that will
		// time out due to the processing overhead.
		//
		// In an ideal world, beacon tx-es shouldn't be gossiped to begin
		// with.
		switch {
		case ctx.IsCheckOnly():
			// During CheckTx do the quick check and only accept own transactions.
			if !staking.NewAddress(ctx.TxSigner()).Equal(ctx.AppState().OwnTxSignerAddress()) {
				return fmt.Errorf("beacon: rejecting non-local beacon tx: %s", ctx.TxSigner())
			}
		case ctx.IsSimulation():
			// No checks needed during local simulation.
		default:
			// During DeliverTx make sure that the transaction comes from the block proposer.
			registryState := registryState.NewMutableState(ctx.State())
			proposerAddr := ctx.BlockContext().Get(api.BlockProposerKey{}).([]byte)
			proposerNodeID, err := registryState.NodeIDByConsensusAddress(ctx, proposerAddr)
			if err != nil {
				return fmt.Errorf("beacon: failed to resolve proposer node: %w", err)
			}
			if !ctx.TxSigner().Equal(proposerNodeID) {
				return fmt.Errorf("beacon: rejecting beacon tx not from proposer (proposer: %s signer: %s)", proposerNodeID, ctx.TxSigner())
			}

			// Also make sure that there is only a single beacon transaction in a block.
			if ctx.BlockContext().Get(beaconTransactionIncludedKey{}).(bool) {
				return fmt.Errorf("beacon: rejecting multiple beacon txes per block")
			}
			ctx.BlockContext().Set(beaconTransactionIncludedKey{}, true)
		}
		return impl.doPVSSTx(ctx, state, params, tx)
	case MethodSetEpoch:
		if !params.DebugMockBackend {
			return fmt.Errorf("beacon: method '%s' is disabled via consensus", MethodSetEpoch)
		}
		return impl.doSetEpochTx(ctx, state, tx)
	default:
		return fmt.Errorf("beacon: invalid method: %s", tx.Method)
	}
}

func (impl *backendPVSS) doPVSSTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	tx *transaction.Transaction,
) error {
	pvssState, err := state.PVSSState(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get PVSS state: %w", err)
	}
	if pvssState == nil {
		return fmt.Errorf("beacon: no PVSS state, round not in progress")
	}

	// Ensure the tx is from a current valid participant.
	registryState := registryState.NewMutableState(ctx.State())
	node, err := registryState.Node(ctx, ctx.TxSigner())
	if err != nil {
		return fmt.Errorf("beacon: tx not from a node: %v", err)
	}
	if node.Beacon == nil {
		return fmt.Errorf("beacon: tx signer missing beacon metadata")
	}
	if pvssState.BadParticipants[ctx.TxSigner()] {
		return fmt.Errorf("beacon: rejecting tx from bad participant")
	}

	participantIdx := -1
	for idx, id := range pvssState.Participants {
		if id.Equal(node.ID) {
			if !pvssState.Instance.Participants[idx].Inner().Equal(node.Beacon.Point.Inner()) {
				return fmt.Errorf("beacon: tx signer point updated in registry")
			}
			participantIdx = idx
			break
		}
	}
	if participantIdx < 0 {
		return fmt.Errorf("beacon: tx signer not a participant in the current round")
	}

	var (
		txFn        func(*api.Context, *beaconState.MutableState, *beacon.PVSSState, *transaction.Transaction, int) (bool, error)
		slashReason staking.SlashReason
	)
	switch tx.Method {
	case beacon.MethodPVSSCommit:
		txFn = impl.doCommitTx
		slashReason = staking.SlashBeaconInvalidCommit
	case beacon.MethodPVSSReveal:
		txFn = impl.doRevealTx
		slashReason = staking.SlashBeaconInvalidReveal
	}
	var shouldSlash bool
	if shouldSlash, err = txFn(ctx, state, pvssState, tx, participantIdx); err != nil {
		ctx.Logger().Error("transaction failed",
			"err", err,
			"node_id", node.ID,
			"method", tx.Method,
		)

		if shouldSlash {
			slashErr := onPVSSMisbehavior(ctx, node.ID, slashReason)
			if slashErr != nil {
				return fmt.Errorf("failed to slash node %s: %w", node.ID, err)
			}
		}

		return err
	}

	// The transaction was a success, update the state.
	if err = state.SetPVSSState(ctx, pvssState); err != nil {
		return fmt.Errorf("beacon: failed to set updated PVSS state: %w", err)
	}

	return nil
}

func (impl *backendPVSS) doCommitTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	pvssState *beacon.PVSSState,
	tx *transaction.Transaction,
	participantIdx int,
) (bool, error) {
	if pvssState.State != beacon.StateCommit {
		return false, fmt.Errorf("beacon: unexpected commit tx")
	}

	var commitTx beacon.PVSSCommit
	if err := cbor.Unmarshal(tx.Body, &commitTx); err != nil {
		return true, fmt.Errorf("beacon: failed to deserialize commit tx: %w", err)
	}

	// Sanity check the commitment.
	if commitTx.Epoch != pvssState.Epoch {
		return false, fmt.Errorf("beacon: epoch mismatch in commit tx: %d (expected %d)", commitTx.Epoch, pvssState.Epoch)
	}
	if commitTx.Round != pvssState.Round {
		return false, fmt.Errorf("beacon: round mismatch in commit tx: %d (expected %d)", commitTx.Round, pvssState.Round)
	}
	if commitTx.Commit == nil {
		return true, fmt.Errorf("beacon: commit tx missing actual commitment")
	}
	if commitTx.Commit.Index != participantIdx {
		return true, fmt.Errorf("beacon: commit tx index mismatch: %d (expected %d)", commitTx.Commit.Index, participantIdx)
	}

	// Suppress duplicate commits.
	if oldCommit := pvssState.Instance.Commits[participantIdx]; oldCommit != nil {
		oldHash, newHash := hash.NewFrom(oldCommit), hash.NewFrom(commitTx.Commit)
		if oldHash.Equal(&newHash) {
			// Don't slash, adversaries can replay txes.
			return false, fmt.Errorf("beacon: commit tx already received for participant: %d", participantIdx)
		}

		return true, fmt.Errorf("beacon: participant attempted to alter commit: %d", participantIdx)
	}

	// Process the commit (CPU INTENSIVE).
	if err := pvssState.Instance.OnCommit(commitTx.Commit); err != nil {
		return true, fmt.Errorf("beacon: failed to proceess commit tx: %w", err)
	}

	return false, nil
}

func (impl *backendPVSS) doRevealTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	pvssState *beacon.PVSSState,
	tx *transaction.Transaction,
	participantIdx int,
) (bool, error) {
	var revealTx beacon.PVSSReveal
	if err := cbor.Unmarshal(tx.Body, &revealTx); err != nil {
		return true, fmt.Errorf("beacon: failed to deserialize reveal tx: %w", err)
	}

	// Sanity check the reveal.
	if revealTx.Epoch != pvssState.Epoch {
		return false, fmt.Errorf("beacon: epoch mismatch in reveal tx: %d (expected %d)", revealTx.Epoch, pvssState.Epoch)
	}
	if revealTx.Round != pvssState.Round {
		return false, fmt.Errorf("beacon: round mismatch in reveal tx: %d (expected %d)", revealTx.Round, pvssState.Round)
	}
	if revealTx.Reveal == nil {
		return true, fmt.Errorf("beacon: reveal tx missing actual reveal")
	}
	if revealTx.Reveal.Index != participantIdx {
		return true, fmt.Errorf("beacon: reveal tx index mismatch: %d (expected %d)", revealTx.Reveal.Index, participantIdx)
	}

	// Suppress duplicate reveals.
	if oldReveal := pvssState.Instance.Reveals[participantIdx]; oldReveal != nil {
		oldHash, newHash := hash.NewFrom(oldReveal), hash.NewFrom(revealTx.Reveal)
		if oldHash.Equal(&newHash) {
			// Don't slash, adversaries can replay txes.
			return false, fmt.Errorf("beacon: reveal tx already received for participant: %d", participantIdx)
		}

		return true, fmt.Errorf("beacon: participant attempted to alter reveal: %d", participantIdx)
	}

	// Check the state to see if this is permitted.
	switch pvssState.State {
	case beacon.StateReveal:
	case beacon.StateCommit:
		return true, fmt.Errorf("beacon: early reveal tx")
	case beacon.StateComplete:
		return false, fmt.Errorf("beacon: ignoring late reveal tx")
	default:
		// Should never happen.
		return false, fmt.Errorf("beacon: unexpected reveal tx")
	}

	// Process the commit (CPU INTENSIVE).
	if err := pvssState.Instance.OnReveal(revealTx.Reveal); err != nil {
		return true, fmt.Errorf("beacon: failed to process reveal tx: %w", err)
	}

	return false, nil
}

func (impl *backendPVSS) doSetEpochTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	tx *transaction.Transaction,
) error {
	// Handle the mock backend SetEpoch transaction.
	now, _, err := state.GetEpoch(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get current epoch: %w", err)
	}

	var epoch beacon.EpochTime
	if err = cbor.Unmarshal(tx.Body, &epoch); err != nil {
		return fmt.Errorf("beacon: failed to deserialize set epoch tx: %w", err)
	}

	// Ensure there is no SetEpoch call in progress.
	pendingMockEpoch, err := state.PVSSPendingMockEpoch(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query mock epoch state: %w", err)
	}
	if pendingMockEpoch != nil {
		// Unless the requested explicit epoch happens to be pending.
		if *pendingMockEpoch == epoch {
			return nil
		}
		return fmt.Errorf("beacon: explicit epoch transition already pending")
	}

	if epoch <= now {
		// Constructing closed timelike curves is left for civilizations
		// that have mastered spacetime metric engineering such as
		// the Xeelee, and has no place in a trivial blockchain project.
		ctx.Logger().Error("explicit epoch transition does not advance time",
			"epoch", now,
			"new_epoch", epoch,
		)
		return fmt.Errorf("beacon: explicit epoch chronology violation")
	}

	if err = state.SetPVSSPendingMockEpoch(ctx, epoch); err != nil {
		return fmt.Errorf("beacon: failed to set pending mock epoch: %w", err)
	}

	ctx.Logger().Info("scheduling explicit epoch transition on round completion",
		"epoch", epoch,
	)

	return nil
}

func (impl *backendPVSS) doEmitPVSSEvent(ctx *api.Context, pvssState *beacon.PVSSState) {
	var event beacon.PVSSEvent
	event.FromState(pvssState)

	ctx.EmitEvent(api.NewEventBuilder(impl.app.Name()).TypedAttribute(&event))
}

func (impl *backendPVSS) appendFailures(pvssState *beacon.PVSSState, failures []signature.PublicKey) {
	if len(failures) == 0 {
		return
	}
	if pvssState.BadParticipants == nil {
		pvssState.BadParticipants = make(map[signature.PublicKey]bool)
	}
	for _, id := range failures {
		pvssState.BadParticipants[id] = true
	}
}

func (impl *backendPVSS) updateNodeStatus(ctx *api.Context, state *beaconState.MutableState, epoch beacon.EpochTime) error {
	registryState := registryState.NewMutableState(ctx.State())
	nodes, err := registryState.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query node list: %w", err)
	}

	for _, node := range nodes {
		nodeStatus, err := registryState.NodeStatus(ctx, node.ID)
		if err != nil {
			return fmt.Errorf("beacon: failed to query node status: %w", err)
		}
		if nodeStatus.ElectionEligibleAfter != beacon.EpochInvalid {
			// This node is not new, and is already eligible.
			continue
		}

		nodeStatus.ElectionEligibleAfter = epoch
		if err = registryState.SetNodeStatus(ctx, node.ID, nodeStatus); err != nil {
			return fmt.Errorf("beacon: failed to update node status: %w", err)
		}
	}

	return nil
}

func validatorsByVotingPower(m map[signature.PublicKey]int64, entropy []byte) ([]signature.PublicKey, error) {
	// Sort the validators lexographically.
	sorted := make([]signature.PublicKey, 0, len(m))
	for mk := range m {
		sorted = append(sorted, mk)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})

	// To try to make tie-breaks fair, shuffle the validator set first
	// if there is entropy available.
	//
	// Note: This just uses the old beacon since there's a bit of a chicken
	// and egg situation.
	if len(entropy) > 0 {
		drbg, err := drbg.New(crypto.SHA512, entropy, nil, validatorEntropyCtx)
		if err != nil {
			return nil, fmt.Errorf("beacon: couldn't instantiate DRBG: %w", err)
		}
		rngSrc := mathrand.New(drbg)
		rng := rand.New(rngSrc)
		rng.Shuffle(len(sorted), func(i, j int) {
			sorted[i], sorted[j] = sorted[j], sorted[i]
		})
	}

	// Stable-sort the by descending voting power.
	sort.SliceStable(sorted, func(i, j int) bool {
		iPower, jPower := m[sorted[i]], m[sorted[j]]
		return iPower > jPower // Reversed sort.
	})

	return sorted, nil
}
