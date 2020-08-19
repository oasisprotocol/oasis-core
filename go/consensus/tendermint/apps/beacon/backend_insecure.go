package beacon

import (
	"encoding/hex"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

type backendInsecure struct {
	app *beaconApplication
}

func (impl *backendInsecure) OnInitChain(
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

	// Arm the initial epoch transition.
	return impl.scheduleEpochTransitionBlock(ctx, state, params.InsecureParameters, doc.Beacon.Base+1)
}

func (impl *backendInsecure) OnBeginBlock(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	req types.RequestBeginBlock,
) error {
	future, err := state.GetFutureEpoch(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get future epoch: %w", err)
	}
	if future == nil {
		return nil
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
	if !params.DebugMockBackend {
		if err = impl.scheduleEpochTransitionBlock(ctx, state, params.InsecureParameters, future.Epoch+1); err != nil {
			return err
		}
	}
	impl.app.doEmitEpochEvent(ctx, future.Epoch)

	// Generate the beacon
	return impl.onEpochChangeBeacon(ctx, state, params, future.Epoch, req)
}

func (impl *backendInsecure) scheduleEpochTransitionBlock(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.InsecureParameters,
	nextEpoch beacon.EpochTime,
) error {
	// Schedule the epoch transition based on block height.
	nextHeight := int64(nextEpoch) * params.Interval
	return impl.app.scheduleEpochTransitionBlock(ctx, state, nextEpoch, nextHeight)
}

func (impl *backendInsecure) onEpochChangeBeacon(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	epoch beacon.EpochTime,
	req types.RequestBeginBlock,
) error {
	var entropyCtx, entropy []byte

	switch params.DebugDeterministic {
	case false:
		entropyCtx = prodEntropyCtx

		height := ctx.BlockHeight()
		if height <= ctx.InitialHeight() {
			// No meaningful previous commit, use the block hash.  This isn't
			// fantastic, but it's only for one epoch.
			ctx.Logger().Debug("onBeaconEpochChange: using block hash as entropy")
			entropy = req.Hash
		} else {
			// Use the previous commit hash as the entropy input, under the theory
			// that the merkle root of all the commits that went into the last
			// block is harder for any single validator to game than the block
			// hash.
			//
			// Note: This is still insecure, and is vulnerable to adversarial
			// manipulation.  If this is a problem, don't use this backend.
			ctx.Logger().Debug("onBeaconEpochChange: using commit hash as entropy")
			entropy = req.Header.GetLastCommitHash()
		}
		if len(entropy) == 0 {
			return fmt.Errorf("beacon: failed to obtain entropy")
		}
	case true:
		// UNSAFE/DEBUG - Deterministic beacon.
		entropyCtx = DebugEntropyCtx
		// We're setting this random seed so that we have suitable
		// committee schedules for Byzantine E2E scenarios, where we
		// want nodes to be scheduled for only one committee.
		//
		// The permutations derived from this on the first epoch
		// need to have (i) an index that's compute worker only and
		// (ii) an index that's merge worker only. See
		// go/oasis-test-runner/scenario/e2e/byzantine.go for the
		// permutations generated from this seed. These permutations
		// are generated independently of the deterministic node IDs.
		entropy = DebugEntropy
	}

	b := GetBeacon(epoch, entropyCtx, entropy)

	ctx.Logger().Debug("onBeaconEpochChange: generated beacon",
		"epoch", epoch,
		"beacon", hex.EncodeToString(b),
		"block_hash", hex.EncodeToString(entropy),
		"height", ctx.BlockHeight(),
	)

	return impl.app.onNewBeacon(ctx, b)
}

func (impl *backendInsecure) ExecuteTx(
	ctx *api.Context,
	state *beaconState.MutableState,
	params *beacon.ConsensusParameters,
	tx *transaction.Transaction,
) error {
	switch tx.Method {
	case MethodSetEpoch:
		if !params.DebugMockBackend {
			return fmt.Errorf("beacon: method '%s' is disabled via consensus", MethodSetEpoch)
		}
		return impl.doTxSetEpoch(ctx, state, tx.Body)
	default:
		return fmt.Errorf("beacon: invalid method: %s", tx.Method)
	}
}

func (impl *backendInsecure) doTxSetEpoch(
	ctx *api.Context,
	state *beaconState.MutableState,
	txBody []byte,
) error {
	now, _, err := state.GetEpoch(ctx)
	if err != nil {
		return err
	}

	var epoch beacon.EpochTime
	if err := cbor.Unmarshal(txBody, &epoch); err != nil {
		return err
	}

	if epoch <= now {
		ctx.Logger().Error("explicit epoch transition does not advance time",
			"epoch", now,
			"new_epoch", epoch,
		)
		return fmt.Errorf("beacon: explicit epoch does not advance time")
	}

	height := ctx.BlockHeight() + 1 // Current height is ctx.BlockHeight() + 1

	ctx.Logger().Info("scheduling explicit epoch transition",
		"epoch", epoch,
		"next_height", height+1,
		"is_check_only", ctx.IsCheckOnly(),
	)

	if err := state.SetFutureEpoch(ctx, epoch, height+1); err != nil {
		return err
	}
	return nil
}
