// Package epochtimemock implements the mock epochtime application.
package epochtimemock

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

var _ abci.Application = (*epochTimeMockApplication)(nil)

type epochTimeMockApplication struct {
	state *abci.ApplicationState
}

func (app *epochTimeMockApplication) Name() string {
	return AppName
}

func (app *epochTimeMockApplication) ID() uint8 {
	return AppID
}

func (app *epochTimeMockApplication) Methods() []transaction.MethodName {
	return Methods
}

func (app *epochTimeMockApplication) Blessed() bool {
	return false
}

func (app *epochTimeMockApplication) Dependencies() []string {
	return nil
}

func (app *epochTimeMockApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *epochTimeMockApplication) OnCleanup() {
}

func (app *epochTimeMockApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	return nil
}

func (app *epochTimeMockApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	state := newMutableState(ctx.State())

	future, err := state.getFutureEpoch()
	if err != nil {
		return fmt.Errorf("BeginBlock: failed to get future epoch: %w", err)
	}
	if future == nil {
		return nil
	}
	defer state.clearFutureEpoch()

	height := ctx.BlockHeight()
	if future.Height != height {
		ctx.Logger().Error("BeginBlock: height mismatch in defered set",
			"height", height,
			"expected_height", future.Height,
		)
		return fmt.Errorf("epochtime_mock: height mismatch in defered set")
	}

	ctx.Logger().Info("setting epoch",
		"epoch", future.Epoch,
		"current_height", height,
	)

	state.setEpoch(future.Epoch, height)
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEpoch, cbor.Marshal(future.Epoch)))

	return nil
}

func (app *epochTimeMockApplication) ExecuteTx(ctx *abci.Context, tx *transaction.Transaction) error {
	state := newMutableState(ctx.State())

	switch tx.Method {
	case MethodSetEpoch:
		var epoch epochtime.EpochTime
		if err := cbor.Unmarshal(tx.Body, &epoch); err != nil {
			return err
		}

		return app.setEpoch(ctx, state, epoch)
	default:
		return fmt.Errorf("epochtime_mock: invalid method: %s", tx.Method)
	}
}

func (app *epochTimeMockApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *epochTimeMockApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *epochTimeMockApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return fmt.Errorf("tendermint/epochtime_mock: unexpected timer")
}

func (app *epochTimeMockApplication) setEpoch(
	ctx *abci.Context,
	state *mutableState,
	epoch epochtime.EpochTime,
) error {
	height := ctx.BlockHeight()

	ctx.Logger().Info("scheduling epoch transition",
		"epoch", epoch,
		"current_height", height,
		"next_height", height+1,
		"is_check_only", ctx.IsCheckOnly(),
	)

	return state.setFutureEpoch(epoch, height+1)
}

// New constructs a new mock epochtime application instance.
func New() abci.Application {
	return &epochTimeMockApplication{}
}
