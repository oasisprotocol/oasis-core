package vault

import (
	"context"

	vaultState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

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
