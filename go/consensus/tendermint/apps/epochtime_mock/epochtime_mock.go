// Package epochtimemock implements the mock epochtime application.
package epochtimemock

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

var _ api.Application = (*epochTimeMockApplication)(nil)

type epochTimeMockApplication struct {
	state api.ApplicationState
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

func (app *epochTimeMockApplication) OnRegister(state api.ApplicationState, md api.MessageDispatcher) {
	app.state = state
}

func (app *epochTimeMockApplication) OnCleanup() {
}

func (app *epochTimeMockApplication) InitChain(ctx *api.Context, request types.RequestInitChain, doc *genesis.Document) error {
	return nil
}

func (app *epochTimeMockApplication) BeginBlock(ctx *api.Context, request types.RequestBeginBlock) (err error) {
	state := newMutableState(ctx.State())

	future, err := state.getFutureEpoch(ctx)
	if err != nil {
		return fmt.Errorf("BeginBlock: failed to get future epoch: %w", err)
	}
	if future == nil {
		return nil
	}

	height := ctx.BlockHeight() + 1
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

	if err = state.setEpoch(ctx, future.Epoch, height); err != nil {
		return fmt.Errorf("epochtime_mock: failed to set epoch: %w", err)
	}
	if err = state.clearFutureEpoch(ctx); err != nil {
		return fmt.Errorf("epochtime_mock: failed to clear future epoch: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyEpoch, cbor.Marshal(future.Epoch)))

	return nil
}

func (app *epochTimeMockApplication) ExecuteMessage(ctx *api.Context, kind, msg interface{}) error {
	return fmt.Errorf("epochtime_mock: unexpected message")
}

func (app *epochTimeMockApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
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

func (app *epochTimeMockApplication) ForeignExecuteTx(ctx *api.Context, other api.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *epochTimeMockApplication) EndBlock(ctx *api.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *epochTimeMockApplication) setEpoch(
	ctx *api.Context,
	state *mutableState,
	epoch epochtime.EpochTime,
) error {
	height := ctx.BlockHeight() + 1

	ctx.Logger().Info("scheduling epoch transition",
		"epoch", epoch,
		"current_height", height,
		"next_height", height+1,
		"is_check_only", ctx.IsCheckOnly(),
	)

	return state.setFutureEpoch(ctx, epoch, height+1)
}

// New constructs a new mock epochtime application instance.
func New() api.Application {
	return &epochTimeMockApplication{}
}
