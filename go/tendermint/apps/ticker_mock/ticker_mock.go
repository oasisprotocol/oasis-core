// Package tickermock implements the mock ticker application.
package tickermock

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

var _ abci.Application = (*tickerMockApplication)(nil)

type tickerMockApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState
}

func (app *tickerMockApplication) Name() string {
	return AppName
}

func (app *tickerMockApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *tickerMockApplication) Blessed() bool {
	return false
}

func (app *tickerMockApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetTick, nil, app.queryGetTick)
}

func (app *tickerMockApplication) OnCleanup() {
}

func (app *tickerMockApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *tickerMockApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *tickerMockApplication) queryGetTick(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	var (
		response QueryGetTickResponse
		err      error
	)
	response.Tick, err = state.getTick()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(response), nil
}

func (app *tickerMockApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "ticker_mock: failed to unmarshal")
	}

	if err := app.executeTx(ctx, app.state.CheckTxTree(), request); err != nil {
		return err
	}

	return nil
}

func (app *tickerMockApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *tickerMockApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	return nil
}

func (app *tickerMockApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	state := newMutableState(app.state.DeliverTxTree())

	isScheduled, err := state.isTickScheduled()
	if err != nil {
		return errors.Wrap(err, "BeginBlock: failed to get scheduled tick")
	}
	if !isScheduled {
		return nil
	}
	defer state.clearScheduledTick() // nolint: errcheck

	app.logger.Info("doing tick")

	tick, err := state.doTick()
	if err != nil {
		return errors.Wrap(err, "BeginBlock: failed to do tick")
	}
	ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
	ctx.EmitTag(TagTick, cbor.Marshal(tick))

	return nil
}

func (app *tickerMockApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "ticker_mock: failed to unmarshal")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *tickerMockApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *tickerMockApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *tickerMockApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
}

func (app *tickerMockApplication) executeTx(
	ctx *abci.Context,
	tree *iavl.MutableTree,
	tx *Tx,
) error {
	state := newMutableState(tree)

	if tx.TxDoTick != nil {
		return app.doTick(ctx, state)
	}
	return errors.New("ticker_mock: invalid argument")
}

func (app *tickerMockApplication) doTick(
	ctx *abci.Context,
	state *mutableState,
) error {
	height := app.state.BlockHeight()

	app.logger.Info("scheduling tick",
		"current_height", height,
		"is_check_only", ctx.IsCheckOnly(),
	)

	return state.scheduleTick()
}

// New constructs a new mock epochtime application instance.
func New() abci.Application {
	return &tickerMockApplication{
		logger: logging.GetLogger("tendermint/ticker_mock"),
	}
}
