// Package epochtimemock implements the mock epochtime application.
package epochtimemock

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

var _ abci.Application = (*epochTimeMockApplication)(nil)

type epochTimeMockApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState
}

func (app *epochTimeMockApplication) Name() string {
	return AppName
}

func (app *epochTimeMockApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *epochTimeMockApplication) Blessed() bool {
	return false
}

func (app *epochTimeMockApplication) Dependencies() []string {
	return nil
}

func (app *epochTimeMockApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetEpoch, nil, app.queryGetEpoch)
}

func (app *epochTimeMockApplication) OnCleanup() {
}

func (app *epochTimeMockApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *epochTimeMockApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *epochTimeMockApplication) queryGetEpoch(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	var (
		response QueryGetEpochResponse
		err      error
	)
	response.Epoch, response.Height, err = state.getEpoch()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(response), nil
}

func (app *epochTimeMockApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "epochtime_mock: failed to unmarshal")
	}

	if err := app.executeTx(ctx, request); err != nil {
		return err
	}

	return nil
}

func (app *epochTimeMockApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *epochTimeMockApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	return nil
}

func (app *epochTimeMockApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	state := newMutableState(ctx.State())

	future, err := state.getFutureEpoch()
	if err != nil {
		return errors.Wrap(err, "BeginBlock: failed to get future epoch")
	}
	if future == nil {
		return nil
	}
	defer state.clearFutureEpoch()

	height := app.state.BlockHeight()
	if future.Height != height {
		app.logger.Error("BeginBlock: height mismatch in defered set",
			"height", height,
			"expected_height", future.Height,
		)
		return errors.New("epochtime_mock: height mismatch in defered set")
	}

	app.logger.Info("setting epoch",
		"epoch", future.Epoch,
		"current_height", height,
	)

	state.setEpoch(future.Epoch, height)
	ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
	ctx.EmitTag(TagEpoch, cbor.Marshal(future.Epoch))

	return nil
}

func (app *epochTimeMockApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "epochtime_mock: failed to unmarshal")
	}

	return app.executeTx(ctx, request)
}

func (app *epochTimeMockApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *epochTimeMockApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *epochTimeMockApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return errors.New("tendermint/epochtime_mock: unexpected timer")
}

func (app *epochTimeMockApplication) executeTx(ctx *abci.Context, tx *Tx) error {
	state := newMutableState(ctx.State())

	if tx.TxSetEpoch != nil {
		return app.setEpoch(ctx, state, tx.TxSetEpoch.Epoch)
	}
	return errors.New("epochtime_mock: invalid argument")
}

func (app *epochTimeMockApplication) setEpoch(
	ctx *abci.Context,
	state *mutableState,
	epoch epochtime.EpochTime,
) error {
	height := app.state.BlockHeight()

	app.logger.Info("scheduling epoch transition",
		"epoch", epoch,
		"current_height", height,
		"next_height", height+1,
		"is_check_only", ctx.IsCheckOnly(),
	)

	return state.setFutureEpoch(epoch, height+1)
}

// New constructs a new mock epochtime application instance.
func New() abci.Application {
	return &epochTimeMockApplication{
		logger: logging.GetLogger("tendermint/epochtime_mock"),
	}
}
