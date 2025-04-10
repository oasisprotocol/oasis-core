package vault

import (
	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/api"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	stakingApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

type Application struct {
	state api.ApplicationState
	md    api.MessageDispatcher
}

func (app *Application) Name() string {
	return AppName
}

func (app *Application) ID() uint8 {
	return AppID
}

func (app *Application) Methods() []transaction.MethodName {
	return vault.Methods
}

// Enabled implements api.TogglableApplication and api.TogglableMessageSubscriber.
func (app *Application) Enabled(ctx *api.Context) (bool, error) {
	state := vaultState.NewImmutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return false, err
	}
	return params.Enabled, nil
}

func (app *Application) Blessed() bool {
	return false
}

func (app *Application) Dependencies() []string {
	return []string{stakingapp.AppName}
}

func (app *Application) OnRegister(md api.MessageDispatcher) {
	app.md = md

	// Subscribe to messages emitted by other apps.
	md.Subscribe(stakingApi.MessageAccountHook, app)
	md.Subscribe(governanceApi.MessageChangeParameters, app)
	md.Subscribe(governanceApi.MessageValidateParameterChanges, app)
}

func (app *Application) OnCleanup() {
}

func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	ctx.SetPriority(AppPriority)

	switch tx.Method {
	case vault.MethodCreate:
		var args vault.Create
		if err := cbor.Unmarshal(tx.Body, &args); err != nil {
			return vault.ErrInvalidArgument
		}
		return app.create(ctx, &args)
	case vault.MethodAuthorizeAction:
		var args vault.AuthorizeAction
		if err := cbor.Unmarshal(tx.Body, &args); err != nil {
			return vault.ErrInvalidArgument
		}
		return app.authorizeAction(ctx, &args)
	case vault.MethodCancelAction:
		var args vault.CancelAction
		if err := cbor.Unmarshal(tx.Body, &args); err != nil {
			return vault.ErrInvalidArgument
		}
		return app.cancelAction(ctx, &args)
	default:
		return vault.ErrInvalidArgument
	}
}

func (app *Application) ExecuteMessage(ctx *api.Context, kind, msg any) (any, error) {
	switch kind {
	case stakingApi.MessageAccountHook:
		// Account hook invocation.
		return app.invokeAccountHook(ctx, msg)
	case governanceApi.MessageValidateParameterChanges:
		// A change parameters proposal is about to be submitted. Validate changes.
		return app.changeParameters(ctx, msg, false)
	case governanceApi.MessageChangeParameters:
		// A change parameters proposal has just been accepted and closed. Validate and apply
		// changes.
		return app.changeParameters(ctx, msg, true)
	default:
		return nil, vault.ErrInvalidArgument
	}
}

func (app *Application) BeginBlock(_ *api.Context) error {
	return nil
}

func (app *Application) EndBlock(_ *api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

// New constructs a new vault application instance.
func New(state api.ApplicationState) *Application {
	return &Application{
		state: state,
	}
}
