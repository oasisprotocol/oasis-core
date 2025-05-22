package vault

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// QueryFactory is the vault query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new vault query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a vault query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	tree, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	state := vaultState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// Query is the vault query.
type Query struct {
	state *vaultState.ImmutableState
}

// NewQuery returns a new vault query backed by the given state.
func NewQuery(state *vaultState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// Vaults implements vault.Query.
func (q *Query) Vaults(ctx context.Context) ([]*vault.Vault, error) {
	return q.state.Vaults(ctx)
}

// Vault implements vault.Query.
func (q *Query) Vault(ctx context.Context, address staking.Address) (*vault.Vault, error) {
	return q.state.Vault(ctx, address)
}

// AddressState implements vault.Query.
func (q *Query) AddressState(ctx context.Context, vault staking.Address, address staking.Address) (*vault.AddressState, error) {
	return q.state.AddressState(ctx, vault, address)
}

// PendingActions implements vault.Query.
func (q *Query) PendingActions(ctx context.Context, address staking.Address) ([]*vault.PendingAction, error) {
	return q.state.PendingActions(ctx, address)
}

// ConsensusParameters implements vault.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*vault.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
