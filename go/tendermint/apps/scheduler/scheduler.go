package scheduler

import (
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	_ abci.Application = (*schedulerApplication)(nil)
)

type schedulerApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
}

func (app *schedulerApplication) Name() string {
	return AppName
}

func (app *schedulerApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *schedulerApplication) Blessed() bool {
	return false
}

func (app *schedulerApplication) GetState(height int64) (interface{}, error) {
	return nil, nil
}

func (app *schedulerApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryTest, nil, app.queryTest)
}

func (app *schedulerApplication) OnCleanup() {}

func (app *schedulerApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *schedulerApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	return nil
}

func (app *schedulerApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *schedulerApplication) InitChain(ctx *abci.Context, req types.RequestInitChain, doc *genesis.Document) {
}

func (app *schedulerApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
	// TODO: We'll later have this for each type of committee.
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		app.logger.Debug("BeginBlock with epoch change",
			"epoch", epoch,
		)
	}
}

func (app *schedulerApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	return nil
}

func (app *schedulerApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *schedulerApplication) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

func (app *schedulerApplication) FireTimer(ctx *abci.Context, t *abci.Timer) {}

func (app *schedulerApplication) queryTest(s interface{}, r interface{}) ([]byte, error) {
	app.logger.Debug("queryTest")
	return nil, nil
}

// New constructs a new scheduler application instance.
func New() abci.Application {
	return &schedulerApplication{
		logger: logging.GetLogger("tendermint/scheduler"),
	}
}
