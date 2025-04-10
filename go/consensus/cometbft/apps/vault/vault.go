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

// Application is a vault application.
type Application struct {
	state api.ApplicationState
	md    api.MessageDispatcher
}

// New constructs a new vault application.
func New(state api.ApplicationState, md api.MessageDispatcher) *Application {
	return &Application{
		state: state,
		md:    md,
	}
}

// Name implements api.Application.
func (app *Application) Name() string {
	return AppName
}

// ID implements api.Application.
func (app *Application) ID() uint8 {
	return AppID
}

// Methods implements api.Application.
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

// Blessed implements api.Application.
func (app *Application) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *Application) Dependencies() []string {
	return []string{stakingapp.AppName}
}

// Subscribe implements api.Application.
func (app *Application) Subscribe() {
	// Subscribe to messages emitted by other apps.
	app.md.Subscribe(stakingApi.MessageAccountHook, app)
	app.md.Subscribe(governanceApi.MessageChangeParameters, app)
	app.md.Subscribe(governanceApi.MessageValidateParameterChanges, app)
}

// OnCleanup implements api.Application.
func (app *Application) OnCleanup() {
}

// ExecuteTx implements api.Application.
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

// ExecuteMessage implements api.MessageSubscriber.
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

// BeginBlock implements api.Application.
func (app *Application) BeginBlock(_ *api.Context) error {
	return nil
}

// EndBlock implements api.Application.
func (app *Application) EndBlock(_ *api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}
