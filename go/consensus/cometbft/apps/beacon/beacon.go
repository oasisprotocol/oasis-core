// Package beacon implements the combined beacon and epochtime
// application.
package beacon

import (
	"encoding/binary"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"
	"golang.org/x/crypto/sha3"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
)

var prodEntropyCtx = []byte("EkB-tmnt")

// Application is a beacon application.
type Application struct {
	backend internalBackend
}

// New constructs a new beacon application.
func New() *Application {
	return &Application{}
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
	return Methods
}

// Blessed implements api.Application.
func (app *Application) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *Application) Dependencies() []string {
	return nil
}

// Subscribe implements api.Application.
func (app *Application) Subscribe() {
}

// OnCleanup implements api.Application.
func (app *Application) OnCleanup() {
}

// BeginBlock implements api.Application.
func (app *Application) BeginBlock(ctx *api.Context) error {
	state := beaconState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query consensus parameters: %w", err)
	}

	if err := app.doInitBackend(params); err != nil {
		return fmt.Errorf("beacon: failed to (re-)initialize backend: %w", err)
	}

	return app.backend.OnBeginBlock(ctx, state, params)
}

// ExecuteMessage implements api.MessageSubscriber.
func (app *Application) ExecuteMessage(*api.Context, any, any) (any, error) {
	return nil, fmt.Errorf("beacon: unexpected message")
}

// ExecuteTx implements api.Application.
func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	if app.backend == nil {
		// Executing a transaction before BeginBlock -- likely during transaction simulation or
		// checks. Fail the transaction, it may be retried.
		return consensus.ErrNoCommittedBlocks
	}

	state := beaconState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query consensus parameters: %w", err)
	}

	ctx.SetPriority(AppPriority)

	return app.backend.ExecuteTx(ctx, state, params, tx)
}

// EndBlock implements api.Application.
func (app *Application) EndBlock(*api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *Application) doEmitEpochEvent(ctx *api.Context, epoch beacon.EpochTime) {
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&beacon.EpochEvent{Epoch: epoch}))
}

func (app *Application) scheduleEpochTransitionBlock(
	ctx *api.Context,
	state *beaconState.MutableState,
	nextEpoch beacon.EpochTime,
	nextHeight int64,
) error {
	ctx.Logger().Info("scheduling epoch transition block",
		"epoch", nextEpoch,
		"next_height", nextHeight,
		"is_check_only", ctx.IsCheckOnly(),
	)

	if err := state.SetFutureEpoch(ctx, nextEpoch, nextHeight); err != nil {
		return fmt.Errorf("beacon: failed to set future epoch from interval: %w", err)
	}
	return nil
}

func (app *Application) onNewBeacon(ctx *api.Context, value []byte) error {
	state := beaconState.NewMutableState(ctx.State())

	if err := state.SetBeacon(ctx, value); err != nil {
		ctx.Logger().Error("onNewBeacon: failed to set beacon",
			"err", err,
		)
		return fmt.Errorf("beacon: failed to set beacon: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&beacon.BeaconEvent{Beacon: value}))

	return nil
}

// insecureBlockEntropy returns insecure entropy based on deterministic block data.
//
// Note that this is insecure and is vulnerable to adversarial manipulation.
func insecureBlockEntropy(ctx *api.Context) []byte {
	var blockHeight [8]byte
	binary.LittleEndian.PutUint64(blockHeight[:], uint64(ctx.BlockHeight()))

	var time [8]byte
	binary.LittleEndian.PutUint64(time[:], uint64(ctx.Now().Unix()))

	h := sha3.New256()
	_, _ = h.Write(blockHeight[:])
	_, _ = h.Write(time[:])
	_, _ = h.Write(ctx.LastStateRootHash())
	return h.Sum(nil)
}

// GetBeacon derives the actual beacon from the epoch and entropy source.
func GetBeacon(epoch beacon.EpochTime, entropyCtx, entropy []byte) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(epoch))

	h := sha3.New256()
	_, _ = h.Write(entropyCtx)
	_, _ = h.Write(entropy)
	_, _ = h.Write(tmp[:])
	return h.Sum(nil)
}
