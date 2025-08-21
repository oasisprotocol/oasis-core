package keymanager

import (
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	api "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets"
	registryapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Application is a key manager application.
type Application struct {
	state api.ApplicationState

	exts         []api.Extension
	methods      []transaction.MethodName
	extsByMethod map[transaction.MethodName]api.Extension
}

// New constructs a new key manager application.
func New(state api.ApplicationState) *Application {
	app := Application{
		state:        state,
		exts:         make([]api.Extension, 0),
		methods:      make([]transaction.MethodName, 0),
		extsByMethod: make(map[transaction.MethodName]api.Extension),
	}

	app.registerExtensions(secrets.New(app.Name(), state))
	app.registerExtensions(churp.New(app.Name(), state))

	return &app
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
	return app.methods
}

// Blessed implements api.Application.
func (app *Application) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *Application) Dependencies() []string {
	return []string{registryapp.AppName}
}

// Subscribe implements api.Application.
func (app *Application) Subscribe() {
}

// OnCleanup implements api.Application.
func (app *Application) OnCleanup() {}

// BeginBlock implements api.Application.
func (app *Application) BeginBlock(ctx *api.Context) error {
	// Prioritize application-specific logic.
	if changed, _ := app.state.EpochChanged(ctx); changed {
		if err := suspendRuntimes(ctx); err != nil {
			return err
		}
	}

	// Proceed with extension-specific logic.
	for _, ext := range app.exts {
		if err := ext.BeginBlock(ctx); err != nil {
			return err
		}
	}

	return nil
}

// ExecuteTx implements api.Application.
func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	ctx.SetPriority(AppPriority)

	ext, ok := app.extsByMethod[tx.Method]
	if !ok {
		return fmt.Errorf("keymanager: invalid method: %s", tx.Method)
	}

	return ext.ExecuteTx(ctx, tx)
}

// EndBlock implements api.Application.
func (app *Application) EndBlock(*api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

// suspendRuntimes suspends runtimes if registering entities no longer possess enough stake
// to cover the entity and runtime deposits.
func suspendRuntimes(ctx *api.Context) error {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	params, err := stakeState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}
	if params.DebugBypassStake {
		return nil
	}

	stakeAcc, err := stakingState.NewStakeAccumulatorCache(ctx)
	if err != nil {
		return fmt.Errorf("failed to create stake accumulator cache: %w", err)
	}
	defer stakeAcc.Discard()

	runtimes, _ := regState.Runtimes(ctx)
	for _, rt := range runtimes {
		if rt.Kind != registry.KindKeyManager {
			continue
		}

		if rt.GovernanceModel == registry.GovernanceConsensus {
			continue
		}

		acctAddr, ok := rt.StakingAddress()
		if !ok {
			// This should never happen.
			ctx.Logger().Error("unknown runtime governance model",
				"rt_id", rt.ID,
				"gov_model", rt.GovernanceModel,
			)
			return fmt.Errorf("unknown runtime governance model on runtime %s: %s", rt.ID, rt.GovernanceModel)
		}

		if err = stakeAcc.CheckStakeClaims(*acctAddr); err == nil {
			continue
		}

		ctx.Logger().Debug("insufficient stake for key manager runtime operation",
			"err", err,
			"entity", rt.EntityID,
			"account", *acctAddr,
		)

		if err := regState.SuspendRuntime(ctx, rt.ID); err != nil {
			return err
		}
	}

	return nil
}

func (app *Application) registerExtensions(exts ...api.Extension) {
	for _, ext := range exts {
		for _, m := range ext.Methods() {
			if _, ok := app.extsByMethod[m]; ok {
				panic(fmt.Sprintf("keymanager: method already registered: %s", m))
			}
			app.extsByMethod[m] = ext
			app.methods = append(app.methods, m)
		}
		app.exts = append(app.exts, ext)
	}
}
