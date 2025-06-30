package staking

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is a staking query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is the staking query interface.
type Query interface {
	// TotalSupply returns the total supply balance.
	TotalSupply(context.Context) (*quantity.Quantity, error)
	// CommonPool returns the balance of the global common pool.
	CommonPool(context.Context) (*quantity.Quantity, error)
	// LastBlockFees returns the last block fees balance.
	LastBlockFees(context.Context) (*quantity.Quantity, error)
	// GovernanceDeposits returns the governance deposits balance.
	GovernanceDeposits(context.Context) (*quantity.Quantity, error)
	// Threshold returns the currently configured threshold.
	Threshold(context.Context, staking.ThresholdKind) (*quantity.Quantity, error)
	// DebondingInterval returns the debonding interval.
	DebondingInterval(context.Context) (beacon.EpochTime, error)
	// Addresses returns the non-empty addresses from the staking ledger.
	Addresses(context.Context) ([]staking.Address, error)
	// CommissionScheduleAddresses returns addresses that have a non empty commission schedule configured.
	CommissionScheduleAddresses(context.Context) ([]staking.Address, error)
	// Account returns the staking account for the given account address.
	Account(context.Context, staking.Address) (*staking.Account, error)
	// DelegationsFor returns the list of (outgoing) delegations for the given
	// owner (delegator).
	DelegationsFor(context.Context, staking.Address) (map[staking.Address]*staking.Delegation, error)
	// DelegationInfosFor returns (outgoing) delegations with additional
	// information for the given owner (delegator).
	DelegationInfosFor(context.Context, staking.Address) (map[staking.Address]*staking.DelegationInfo, error)
	// DelegationsTo returns the list of (incoming) delegations to the given
	// account.
	DelegationsTo(context.Context, staking.Address) (map[staking.Address]*staking.Delegation, error)
	// DebondingDelegationsFor returns the list of (outgoing) debonding
	// delegations for the given owner (delegator).
	DebondingDelegationsFor(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error)
	// DebondingDelegationInfosFor returns (outgoing) debonding delegations
	// with additional information for the given owner (delegator).
	DebondingDelegationInfosFor(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegationInfo, error)
	// DebondingDelegationsTo returns the list of (incoming) debonding
	// delegations to the given account.
	DebondingDelegationsTo(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*staking.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*staking.ConsensusParameters, error)
}

// StateQueryFactory is a staking state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new staking query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a staking query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}

// LightQueryFactory is a staking light query factory.
type LightQueryFactory struct {
	querier *app.LightQueryFactory
}

// NewLightQueryFactory returns a new staking query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) QueryFactory {
	return &LightQueryFactory{
		querier: app.NewLightQueryFactory(rooter, syncer),
	}
}

// QueryAt returns a staking query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
