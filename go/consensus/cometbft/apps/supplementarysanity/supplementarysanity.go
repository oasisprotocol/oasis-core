package supplementarysanity

import (
	"fmt"
	"math/rand"

	"github.com/cometbft/cometbft/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

var (
	logger = logging.GetLogger("supplementarysanity")

	_ api.Application = (*Application)(nil)
)

// Application is a non-normative mux app that performs additional checks on the consensus state.
// It should not alter the CometBFT application state.
// It's okay for it to have this additional local state, because it won't affect anything that needs to be agreed upon
// in consensus.
type Application struct {
	state           api.ApplicationState
	interval        int64
	currentInterval int64
	checkHeight     int64
}

func (app *Application) Name() string {
	return AppName
}

func (app *Application) ID() uint8 {
	return AppID
}

func (app *Application) Methods() []transaction.MethodName {
	return nil
}

func (app *Application) Blessed() bool {
	return false
}

func (app *Application) Dependencies() []string {
	return []string{stakingState.AppName}
}

func (app *Application) OnRegister(api.MessageDispatcher) {
}

func (app *Application) OnCleanup() {
}

func (app *Application) ExecuteMessage(*api.Context, any, any) (any, error) {
	return nil, fmt.Errorf("supplementarysanity: unexpected message")
}

func (app *Application) ExecuteTx(*api.Context, *transaction.Transaction) error {
	return fmt.Errorf("supplementarysanity: unexpected transaction")
}

func (app *Application) InitChain(*api.Context, types.RequestInitChain, *genesis.Document) error {
	return nil
}

func (app *Application) BeginBlock(*api.Context) error {
	return nil
}

func (app *Application) EndBlock(ctx *api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, app.endBlockImpl(ctx)
}

func (app *Application) endBlockImpl(ctx *api.Context) error {
	height := ctx.BlockHeight()

	if height == 1 {
		logger.Debug("skipping checks before InitChain")
		return nil
	}

	newInterval := height / app.interval
	if newInterval != app.currentInterval {
		minimum := height % app.interval
		offset := rand.Int63n(app.interval-minimum) + minimum
		app.currentInterval = newInterval
		app.checkHeight = newInterval*app.interval + offset
		logger.Debug("Entering new interval",
			"height", height,
			"check_height", app.checkHeight,
		)
	}

	if height != app.checkHeight {
		return nil
	}

	logger.Debug("checking this block", "height", height)

	now, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		return fmt.Errorf("cometbft/supplementarysanity: failed to GetEpoch: %w", err)
	}
	for _, tt := range []struct {
		name    string
		checker func(ctx *api.Context, now beacon.EpochTime) error
	}{
		{"checkEpochTime", checkEpochTime},
		{"checkRegistry", checkRegistry},
		{"checkRootHash", checkRootHash},
		{"checkStaking", checkStaking},
		{"checkKeyManager", checkKeyManager},
		{"checkScheduler", checkScheduler},
		{"checkBeacon", checkBeacon},
		{"checkConsensus", checkConsensus},
		{"checkGovernance", checkGovernance},
		{"checkHalt", checkHalt},
		{"checkStakeClaims", checkStakeClaims},
	} {
		if err := tt.checker(ctx, now); err != nil {
			return fmt.Errorf("cometbft/supplementarysanity: check failed %s: %w", tt.name, err)
		}
	}

	return nil
}

func New(state api.ApplicationState, interval int64) *Application {
	return &Application{
		state:    state,
		interval: interval,
	}
}
