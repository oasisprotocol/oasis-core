// Package beacon implements the beacon application.
package beacon

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/crypto/sha3"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

var (
	prodEntropyCtx  = []byte("EkB-tmnt")
	DebugEntropyCtx = []byte("Ekb-Dumm")

	_ api.Application = (*beaconApplication)(nil)
)

type beaconApplication struct {
	state api.ApplicationState
}

func (app *beaconApplication) Name() string {
	return AppName
}

func (app *beaconApplication) ID() uint8 {
	return AppID
}

func (app *beaconApplication) Methods() []transaction.MethodName {
	return nil
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
	if changed, beaconEpoch := app.state.EpochChanged(ctx); changed {
		return app.onBeaconEpochChange(ctx, beaconEpoch, req)
	}
	return nil
}

func (app *beaconApplication) ExecuteMessage(ctx *api.Context, kind, msg interface{}) error {
	return fmt.Errorf("beacon: unexpected message")
}

func (app *beaconApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	return fmt.Errorf("beacon: unexpected transaction")
}

func (app *beaconApplication) ForeignExecuteTx(ctx *api.Context, other api.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *beaconApplication) EndBlock(ctx *api.Context, req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *beaconApplication) onBeaconEpochChange(ctx *api.Context, epoch epochtime.EpochTime, req types.RequestBeginBlock) error {
	var entropyCtx, entropy []byte

	state := beaconState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}

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
			// TODO: This still isn't ideal, and an entirely different beacon
			// entropy source should be written, be it based around SCRAPE,
			// a VDF, naive commit-reveal, or even just calling an SGX enclave.
			ctx.Logger().Debug("onBeaconEpochChange: using commit hash as entropy")
			entropy = req.Header.GetLastCommitHash()
		}
		if len(entropy) == 0 {
			return fmt.Errorf("onBeaconEpochChange: failed to obtain entropy")
		}
	case true:
		// UNSAFE/DEBUG - Deterministic beacon.
		entropyCtx = DebugEntropyCtx
		// We're setting this random seed so that we have suitable committee schedules for Byzantine E2E scenarios,
		// where we want nodes to be scheduled for only one committee. The permutations derived from this on the first
		// epoch need to have (i) an index that's compute worker only and (ii) an index that's merge worker only. See
		// /go/oasis-test-runner/scenario/e2e/byzantine.go for the permutations generated from this seed. These
		// permutations are generated independently of the deterministic node IDs.
		entropy = []byte("If you change this, you will fuck up the byzantine tests!!")
	}

	b := GetBeacon(epoch, entropyCtx, entropy)

	ctx.Logger().Debug("onBeaconEpochChange: generated beacon",
		"epoch", epoch,
		"beacon", hex.EncodeToString(b),
		"block_hash", hex.EncodeToString(entropy),
		"height", ctx.BlockHeight(),
	)

	return app.onNewBeacon(ctx, b)
}

func (app *beaconApplication) onNewBeacon(ctx *api.Context, beacon []byte) error {
	state := beaconState.NewMutableState(ctx.State())

	if err := state.SetBeacon(ctx, beacon); err != nil {
		ctx.Logger().Error("onNewBeacon: failed to set beacon",
			"err", err,
		)
		return fmt.Errorf("tendermint/beacon: failed to set beacon: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyGenerated, beacon))

	return nil
}

// New constructs a new beacon application instance.
func New() api.Application {
	return &beaconApplication{}
}

func GetBeacon(beaconEpoch epochtime.EpochTime, entropyCtx, entropy []byte) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(beaconEpoch))

	h := sha3.New256()
	_, _ = h.Write(entropyCtx)
	_, _ = h.Write(entropy)
	_, _ = h.Write(tmp[:])
	return h.Sum(nil)
}
