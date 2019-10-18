// Package beacon implements the beacon application.
package beacon

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	"golang.org/x/crypto/sha3"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

var (
	errUnexpectedTransaction = errors.New("beacon: unexpected transaction")
	errUnexpectedTimer       = errors.New("beacon: unexpected timer")

	prodEntropyCtx  = []byte("EkB-tmnt")
	debugEntropyCtx = []byte("Ekb-Dumm")

	_ abci.Application = (*beaconApplication)(nil)
)

type beaconApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.Backend

	cfg *beacon.Config
}

func (app *beaconApplication) Name() string {
	return AppName
}

func (app *beaconApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *beaconApplication) Blessed() bool {
	return false
}

func (app *beaconApplication) Dependencies() []string {
	return nil
}

func (app *beaconApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *beaconApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *beaconApplication) OnCleanup() {
}

func (app *beaconApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *beaconApplication) InitChain(ctx *abci.Context, req types.RequestInitChain, doc *genesis.Document) error {
	// Note: If we ever decide that we need a beacon for the 0th epoch
	// (that is *only* for the genesis state), it should be initiailized
	// here.
	//
	// It is not super important for now as the epoch will transition
	// immediately on the first block under normal circumstances.
	return nil
}

func (app *beaconApplication) BeginBlock(ctx *abci.Context, req types.RequestBeginBlock) error {
	if changed, beaconEpoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onBeaconEpochChange(ctx, beaconEpoch, req)
	}
	return nil
}

func (app *beaconApplication) ExecuteTx(ctx *abci.Context, tx []byte) error {
	return errUnexpectedTransaction
}

func (app *beaconApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *beaconApplication) EndBlock(ctx *abci.Context, req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *beaconApplication) FireTimer(ctx *abci.Context, t *abci.Timer) error {
	return errUnexpectedTimer
}

func (app *beaconApplication) onBeaconEpochChange(ctx *abci.Context, epoch epochtime.EpochTime, req types.RequestBeginBlock) error {
	var entropyCtx, entropy []byte

	switch app.cfg.DebugDeterministic {
	case false:
		entropyCtx = prodEntropyCtx

		height := app.state.BlockHeight()
		if height <= 1 {
			// No meaningful previous commit, use the block hash.  This isn't
			// fantastic, but it's only for one epoch.
			app.logger.Debug("onBeaconEpochChange: using block hash as entropy")
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
			app.logger.Debug("onBeaconEpochChange: using commit hash as entropy")
			entropy = req.Header.GetLastCommitHash()
		}
		if len(entropy) == 0 {
			return errors.New("onBeaconEpochChange: failed to obtain entropy")
		}
	case true:
		// UNSAFE/DEBUG - Deterministic beacon.
		entropyCtx = debugEntropyCtx
	}

	b := getBeacon(epoch, entropyCtx, entropy)

	app.logger.Debug("onBeaconEpochChange: generated beacon",
		"epoch", epoch,
		"beacon", hex.EncodeToString(b),
		"block_hash", hex.EncodeToString(entropy),
		"height", app.state.BlockHeight(),
	)

	return app.onNewBeacon(ctx, b)
}

func (app *beaconApplication) onNewBeacon(ctx *abci.Context, beacon []byte) error {
	state := NewMutableState(ctx.State())

	if err := state.setBeacon(beacon); err != nil {
		app.logger.Error("onNewBeacon: failed to set beacon",
			"err", err,
		)
		return errors.Wrap(err, "tendermint/beacon: failed to set beacon")
	}

	ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
	ctx.EmitTag(TagGenerated, beacon)

	return nil
}

// New constructs a new beacon application instance.
func New(timeSource epochtime.Backend, cfg *beacon.Config) abci.Application {
	app := &beaconApplication{
		logger:     logging.GetLogger("tendermint/beacon"),
		timeSource: timeSource,
		cfg:        cfg,
	}
	if cfg.DebugDeterministic {
		app.logger.Warn("Determistic beacon entropy is NOT FOR PRODUCTION USE")
	}

	return app
}

func getBeacon(beaconEpoch epochtime.EpochTime, entropyCtx []byte, entropy []byte) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(beaconEpoch))

	h := sha3.New256()
	_, _ = h.Write(entropyCtx)
	_, _ = h.Write(entropy)
	_, _ = h.Write(tmp[:])
	return h.Sum(nil)
}
