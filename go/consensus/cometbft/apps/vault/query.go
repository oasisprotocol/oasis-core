package vault

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// Query is the vault query interface.
type Query interface {
	Vaults(context.Context) ([]*vault.Vault, error)
	Vault(context.Context, staking.Address) (*vault.Vault, error)
	AddressState(context.Context, staking.Address, staking.Address) (*vault.AddressState, error)
	PendingActions(context.Context, staking.Address) ([]*vault.PendingAction, error)
	Genesis(context.Context) (*vault.Genesis, error)
	ConsensusParameters(context.Context) (*vault.ConsensusParameters, error)
}

// QueryFactory is the vault query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the vault query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &vaultQuerier{
		state: vaultState.NewImmutableState(state),
	}, nil
}

type vaultQuerier struct {
	state *vaultState.ImmutableState
}

func (q *vaultQuerier) Vaults(ctx context.Context) ([]*vault.Vault, error) {
	return q.state.Vaults(ctx)
}

func (q *vaultQuerier) Vault(ctx context.Context, address staking.Address) (*vault.Vault, error) {
	return q.state.Vault(ctx, address)
}

func (q *vaultQuerier) AddressState(ctx context.Context, vault staking.Address, address staking.Address) (*vault.AddressState, error) {
	return q.state.AddressState(ctx, vault, address)
}

func (q *vaultQuerier) PendingActions(ctx context.Context, address staking.Address) ([]*vault.PendingAction, error) {
	return q.state.PendingActions(ctx, address)
}

func (q *vaultQuerier) ConsensusParameters(ctx context.Context) (*vault.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

func (app *Application) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
