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
func (qf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := vaultState.NewImmutableStateAt(ctx, qf.state, height)
	if err != nil {
		return nil, err
	}
	return &vaultQuerier{state}, nil
}

type vaultQuerier struct {
	state *vaultState.ImmutableState
}

func (vq *vaultQuerier) Vaults(ctx context.Context) ([]*vault.Vault, error) {
	return vq.state.Vaults(ctx)
}

func (vq *vaultQuerier) Vault(ctx context.Context, address staking.Address) (*vault.Vault, error) {
	return vq.state.Vault(ctx, address)
}

func (vq *vaultQuerier) AddressState(ctx context.Context, vault staking.Address, address staking.Address) (*vault.AddressState, error) {
	return vq.state.AddressState(ctx, vault, address)
}

func (vq *vaultQuerier) PendingActions(ctx context.Context, address staking.Address) ([]*vault.PendingAction, error) {
	return vq.state.PendingActions(ctx, address)
}

func (vq *vaultQuerier) ConsensusParameters(ctx context.Context) (*vault.ConsensusParameters, error) {
	return vq.state.ConsensusParameters(ctx)
}

func (app *vaultApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
