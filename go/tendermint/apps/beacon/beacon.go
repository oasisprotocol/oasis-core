// Package beacon implements the beacon application.
package beacon

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

var (
	errUnexpectedTransaction = errors.New("beacon: unexpected transaction")

	entropyCtx = []byte("EkB-tmnt")

	_ abci.Application = (*beaconApplication)(nil)
)

type beaconApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
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

func (app *beaconApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *beaconApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetBeacon, api.QueryGetByEpochRequest{}, app.queryGetBeacon)
}

func (app *beaconApplication) OnCleanup() {
}

func (app *beaconApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *beaconApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	return errUnexpectedTransaction
}

func (app *beaconApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
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
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onEpochChange(ctx, epoch, req)
	}
	return nil
}

func (app *beaconApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	return errUnexpectedTransaction
}

func (app *beaconApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *beaconApplication) EndBlock(req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *beaconApplication) FireTimer(ctx *abci.Context, t *abci.Timer) {
}

func (app *beaconApplication) queryGetBeacon(s interface{}, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByEpochRequest)
	state := s.(*immutableState)
	return state.GetBeacon(request.Epoch)
}

func (app *beaconApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime, req types.RequestBeginBlock) error {
	b := getBeacon(epoch, req.Hash)

	app.logger.Debug("onEpochChange: generated beacon",
		"epoch", epoch,
		"beacon", hex.EncodeToString(b),
		"block_hash", hex.EncodeToString(req.Hash),
		"height", app.state.BlockHeight(),
	)

	return app.onNewBeacon(ctx, &beacon.GenerateEvent{Epoch: epoch, Beacon: b})
}

func (app *beaconApplication) onNewBeacon(ctx *abci.Context, event *beacon.GenerateEvent) error {
	state := NewMutableState(app.state.DeliverTxTree())

	if err := state.setBeacon(event); err != nil {
		app.logger.Error("onNewBeacon: failed to set beacon",
			"err", err,
		)
		return errors.Wrap(err, "tendermint/beacon: failed to set beacon")
	}

	ctx.EmitTag(api.TagApplication, []byte(app.Name()))
	ctx.EmitTag(TagGenerated, cbor.Marshal(event))

	return nil
}

// New constructs a new beacon application instance.
func New(timeSource epochtime.BlockBackend) abci.Application {
	return &beaconApplication{
		logger:     logging.GetLogger("tendermint/beacon"),
		timeSource: timeSource,
	}
}

func getBeacon(epoch epochtime.EpochTime, entropy []byte) []byte {
	// TODO: This isn't a great source of entropy and is likely vulnerable to
	// being gamed by at least the validators.
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(epoch))

	h := sha512.New512_256()
	_, _ = h.Write(entropyCtx)
	_, _ = h.Write(entropy)
	_, _ = h.Write(tmp[:])
	return h.Sum(nil)
}
