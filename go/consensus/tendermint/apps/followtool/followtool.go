package followtool

import (
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingstate "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	"github.com/oasislabs/oasis-core/go/genesis/api"
)

var (
	logger = logging.GetLogger("followtool")

	_ abci.Application = (*followToolApplication)(nil)
)

// followToolApplication is a non-normative mux app that performs additional checks on the consensus state.
// It should not alter the Tendermint application state.
type followToolApplication struct {
	state *abci.ApplicationState
}

func (app *followToolApplication) Name() string {
	return AppName
}

func (app *followToolApplication) ID() uint8 {
	return AppID
}

func (app *followToolApplication) Methods() []transaction.MethodName {
	return nil
}

func (app *followToolApplication) Blessed() bool {
	return false
}

func (app *followToolApplication) Dependencies() []string {
	return []string{stakingstate.AppName}
}

func (app *followToolApplication) QueryFactory() interface{} {
	return nil
}

func (app *followToolApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *followToolApplication) OnCleanup() {
}

func (app *followToolApplication) ExecuteTx(*abci.Context, *transaction.Transaction) error {
	return errors.New("followtool: unexpected transaction")
}

func (app *followToolApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *followToolApplication) InitChain(*abci.Context, types.RequestInitChain, *api.Document) error {
	return nil
}

func (app *followToolApplication) BeginBlock(*abci.Context, types.RequestBeginBlock) error {
	return nil
}

func (app *followToolApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	if request.Height == 1 {
		logger.Debug("skipping total supply check on first block")
	} else {
		if err := checkNonzeroSupply(ctx.State()); err != nil {
			return types.ResponseEndBlock{}, errors.Wrap(err, "checkNonzeroSupply")
		}
	}

	return types.ResponseEndBlock{}, nil
}

func (app *followToolApplication) FireTimer(*abci.Context, *abci.Timer) error {
	return errors.New("followtool: unexpected timer")
}

func New() abci.Application {
	return &followToolApplication{}
}
