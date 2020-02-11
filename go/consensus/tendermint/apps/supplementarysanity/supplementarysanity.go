package supplementarysanity

import (
	"math/rand"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/genesis/api"
)

var (
	logger = logging.GetLogger("supplementarysanity")

	_ abci.Application = (*supplementarySanityApplication)(nil)
)

// supplementarySanityApplication is a non-normative mux app that performs additional checks on the consensus state.
// It should not alter the Tendermint application state.
// It's okay for it to have this additional local state, because it won't affect anything that needs to be agreed upon
// in consensus.
type supplementarySanityApplication struct {
	state           abci.ApplicationState
	interval        int64
	currentInterval int64
	checkHeight     int64
}

func (app *supplementarySanityApplication) Name() string {
	return AppName
}

func (app *supplementarySanityApplication) ID() uint8 {
	return AppID
}

func (app *supplementarySanityApplication) Methods() []transaction.MethodName {
	return nil
}

func (app *supplementarySanityApplication) Blessed() bool {
	return false
}

func (app *supplementarySanityApplication) Dependencies() []string {
	return []string{stakingState.AppName}
}

func (app *supplementarySanityApplication) QueryFactory() interface{} {
	return nil
}

func (app *supplementarySanityApplication) OnRegister(state abci.ApplicationState) {
	app.state = state
}

func (app *supplementarySanityApplication) OnCleanup() {
}

func (app *supplementarySanityApplication) ExecuteTx(*abci.Context, *transaction.Transaction) error {
	return errors.New("supplementarysanity: unexpected transaction")
}

func (app *supplementarySanityApplication) ForeignExecuteTx(*abci.Context, abci.Application, *transaction.Transaction) error {
	return nil
}

func (app *supplementarySanityApplication) InitChain(*abci.Context, types.RequestInitChain, *api.Document) error {
	return nil
}

func (app *supplementarySanityApplication) BeginBlock(*abci.Context, types.RequestBeginBlock) error {
	return nil
}

func (app *supplementarySanityApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, app.endBlockImpl(ctx, request)
}

func (app *supplementarySanityApplication) endBlockImpl(ctx *abci.Context, request types.RequestEndBlock) error {
	if request.Height == 1 {
		logger.Debug("skipping checks before InitChain")
		return nil
	}

	newInterval := request.Height / app.interval
	if newInterval != app.currentInterval {
		min := request.Height % app.interval
		offset := rand.Int63n(app.interval-min) + min
		app.currentInterval = newInterval
		app.checkHeight = newInterval*app.interval + offset
		logger.Debug("Entering new interval",
			"height", request.Height,
			"check_height", app.checkHeight,
		)
	}

	if request.Height != app.checkHeight {
		return nil
	}

	logger.Debug("checking this block", "height", request.Height)

	now, err := app.state.GetEpoch(ctx.Ctx(), ctx.BlockHeight()+1)
	if err != nil {
		return errors.Wrap(err, "GetEpoch")
	}
	state := ctx.State()
	for _, tt := range []struct {
		name    string
		checker func(state *iavl.MutableTree, now epochtime.EpochTime) error
	}{
		{"checkEpochTime", checkEpochTime},
		{"checkRegistry", checkRegistry},
		{"checkRootHash", checkRootHash},
		{"checkStaking", checkStaking},
		{"checkKeyManager", checkKeyManager},
		{"checkScheduler", checkScheduler},
		{"checkBeacon", checkBeacon},
		{"checkConsensus", checkConsensus},
		{"checkHalt", checkHalt},
		{"checkStakeClaims", checkStakeClaims},
	} {
		if err := tt.checker(state, now); err != nil {
			return errors.Wrap(err, tt.name)
		}
	}

	return nil
}

func (app *supplementarySanityApplication) FireTimer(*abci.Context, *abci.Timer) error {
	return errors.New("supplementarysanity: unexpected timer")
}

func New(interval int64) abci.Application {
	return &supplementarySanityApplication{
		interval: interval,
	}
}
