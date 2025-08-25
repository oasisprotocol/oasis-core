package beacon

import (
	"encoding/hex"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

type backendInsecure struct {
	app *Application
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
) error {
	future, err := state.GetFutureEpoch(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to get future epoch: %w", err)
	}
	if future == nil {
		return nil
	}

	height := ctx.CurrentHeight()
	switch {
	case future.Height < height:
		// What the fuck, we missed transitioning the epoch?
		ctx.Logger().Error("height mismatch in deferred set",
			"height", height,
			"expected_height", future.Height,
		)
		return fmt.Errorf("beacon: height mismatch in deferred set")
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
	return impl.onEpochChangeBeacon(ctx, future.Epoch)
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
	epoch beacon.EpochTime,
) error {
	var entropy []byte

	entropyCtx := prodEntropyCtx
	// Use the block hash for entropy. This is insecure, and is vulnerable to adversarial
	// manipulation.  If this is a problem, don't use this backend.
	ctx.Logger().Debug("onBeaconEpochChange: using block hash as entropy")
	entropy = insecureBlockEntropy(ctx)

	b := GetBeacon(epoch, entropyCtx, entropy)

	ctx.Logger().Debug("onBeaconEpochChange: generated beacon",
		"epoch", epoch,
		"beacon", hex.EncodeToString(b),
		"block_hash", hex.EncodeToString(entropy),
		"height", ctx.LastHeight(),
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
	case beacon.MethodSetEpoch:
		if !params.DebugMockBackend {
			return fmt.Errorf("beacon: method '%s' is disabled via consensus", beacon.MethodSetEpoch)
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

	height := ctx.CurrentHeight()

	ctx.Logger().Info("scheduling explicit epoch transition",
		"epoch", epoch,
		"next_height", height+1,
		"is_check_only", ctx.IsCheckOnly(),
	)

	return state.SetFutureEpoch(ctx, epoch, height+1)
}
