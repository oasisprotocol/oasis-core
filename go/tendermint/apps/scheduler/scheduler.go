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

func (app *schedulerApplication) GetState(int64) (interface{}, error) {}

func (app *schedulerApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
}

func (app *schedulerApplication) OnCleanup() {}

func (app *schedulerApplication) SetOption(types.RequestSetOption) types.ResponseSetOption {}

func (app *schedulerApplication) CheckTx(*abci.Context, []byte) error {}

func (app *schedulerApplication) ForeignCheckTx(*abci.Context, abci.Application, []byte) error {}

func (app *schedulerApplication) InitChain(*abci.Context, types.RequestInitChain, *genesis.Document) {}

func (app *schedulerApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
}

func (app *schedulerApplication) DeliverTx(*abci.Context, []byte) error {}

func (app *schedulerApplication) ForeignDeliverTx(*abci.Context, abci.Application, []byte) error {}

func (app *schedulerApplication) EndBlock(types.RequestEndBlock) types.ResponseEndBlock {}

func (app *schedulerApplication) FireTimer(*abci.Context, *abci.Timer) {}
