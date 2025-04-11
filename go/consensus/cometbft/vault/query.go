package vault

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// QueryFactory is a vault query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a vault query implementation.
type Query interface {
	// Vaults returns all of the registered vaults.
	Vaults(context.Context) ([]*vault.Vault, error)
	// Vault returns information about the given vault.
	Vault(context.Context, staking.Address) (*vault.Vault, error)
	// AddressState returns the state information for the given source address.
	AddressState(context.Context, staking.Address, staking.Address) (*vault.AddressState, error)
	// PendingActions returns the list of pending actions for the given vault.
	PendingActions(context.Context, staking.Address) ([]*vault.PendingAction, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*vault.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*vault.ConsensusParameters, error)
}

// StateQueryFactory is a vault state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new vault query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a vault query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
