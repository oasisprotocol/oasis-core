// Package beacon implements the combined beacon and epochtime
// application.
package beacon

import (
	"encoding/binary"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/crypto/sha3"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
)

var (
	prodEntropyCtx = []byte("EkB-tmnt")

	_ api.Application = (*beaconApplication)(nil)
)

type beaconApplication struct {
	state api.ApplicationState

	backend internalBackend
}

func (app *beaconApplication) Name() string {
	return AppName
}

func (app *beaconApplication) ID() uint8 {
	return AppID
}

func (app *beaconApplication) Methods() []transaction.MethodName {
	return Methods
}

func (app *beaconApplication) Blessed() bool {
	return false
}

func (app *beaconApplication) Dependencies() []string {
	return nil
}

func (app *beaconApplication) OnRegister(state api.ApplicationState, md api.MessageDispatcher) {
	app.state = state
}

func (app *beaconApplication) OnCleanup() {
}

func (app *beaconApplication) BeginBlock(ctx *api.Context, req types.RequestBeginBlock) error {
	state := beaconState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query consensus parameters: %w", err)
	}

	if err := app.doInitBackend(params); err != nil {
		return fmt.Errorf("beacon: failed to (re-)initialize backend: %w", err)
	}

	return app.backend.OnBeginBlock(ctx, state, params, req)
}

func (app *beaconApplication) ExecuteMessage(ctx *api.Context, kind, msg interface{}) (interface{}, error) {
	return nil, fmt.Errorf("beacon: unexpected message")
}

func (app *beaconApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	state := beaconState.NewMutableState(ctx.State())

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("beacon: failed to query consensus parameters: %w", err)
	}

	return app.backend.ExecuteTx(ctx, state, params, tx)
}

func (app *beaconApplication) EndBlock(ctx *api.Context, req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *beaconApplication) doEmitEpochEvent(ctx *api.Context, epoch beacon.EpochTime) {
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEpoch, cbor.Marshal(epoch)))
}

func (app *beaconApplication) scheduleEpochTransitionBlock(
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

func (app *beaconApplication) onNewBeacon(ctx *api.Context, beacon []byte) error {
	state := beaconState.NewMutableState(ctx.State())

	if err := state.SetBeacon(ctx, beacon); err != nil {
		ctx.Logger().Error("onNewBeacon: failed to set beacon",
			"err", err,
		)
		return fmt.Errorf("beacon: failed to set beacon: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyBeacon, beacon))

	return nil
}

// New constructs a new beacon application instance.
func New() api.Application {
	return &beaconApplication{}
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
