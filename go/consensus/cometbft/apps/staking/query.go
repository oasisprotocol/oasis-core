package staking

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// QueryFactory is the staking query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new staking query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a staking query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return NewQuery(stakingState.NewImmutableState(state)), nil
}

// Query is the staking query.
type Query struct {
	state *stakingState.ImmutableState
}

// NewQuery returns a new staking query backed by the given state.
func NewQuery(state *stakingState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// TotalSupply implements staking.Query.
func (q *Query) TotalSupply(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.TotalSupply(ctx)
}

// CommonPool implements staking.Query.
func (q *Query) CommonPool(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.CommonPool(ctx)
}

// LastBlockFees implements staking.Query.
func (q *Query) LastBlockFees(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.LastBlockFees(ctx)
}

// GovernanceDeposits implements staking.Query.
func (q *Query) GovernanceDeposits(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.GovernanceDeposits(ctx)
}

// Threshold implements staking.Query.
func (q *Query) Threshold(ctx context.Context, kind staking.ThresholdKind) (*quantity.Quantity, error) {
	thresholds, err := q.state.Thresholds(ctx)
	if err != nil {
		return nil, err
	}

	threshold, ok := thresholds[kind]
	if !ok {
		return nil, staking.ErrInvalidThreshold
	}
	return &threshold, nil
}

// DebondingInterval implements staking.Query.
func (q *Query) DebondingInterval(ctx context.Context) (beacon.EpochTime, error) {
	return q.state.DebondingInterval(ctx)
}

// Addresses implements staking.Query.
func (q *Query) Addresses(ctx context.Context) ([]staking.Address, error) {
	return q.state.Addresses(ctx)
}

// CommissionScheduleAddresses implements staking.Query.
func (q *Query) CommissionScheduleAddresses(ctx context.Context) ([]staking.Address, error) {
	return q.state.CommissionScheduleAddresses(ctx)
}

// Account implements staking.Query.
func (q *Query) Account(ctx context.Context, addr staking.Address) (*staking.Account, error) {
	switch {
	case addr.Equal(staking.CommonPoolAddress):
		cp, err := q.state.CommonPool(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *cp,
			},
		}, nil
	case addr.Equal(staking.FeeAccumulatorAddress):
		fa, err := q.state.LastBlockFees(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *fa,
			},
		}, nil
	case addr.Equal(staking.GovernanceDepositsAddress):
		gd, err := q.state.GovernanceDeposits(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *gd,
			},
		}, nil

	default:
		return q.state.Account(ctx, addr)
	}
}

// DelegationsFor implements staking.Query.
func (q *Query) DelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return q.state.DelegationsFor(ctx, addr)
}

// DelegationInfosFor implements staking.Query.
func (q *Query) DelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.DelegationInfo, error) {
	delegations, err := q.state.DelegationsFor(ctx, addr)
	if err != nil {
		return nil, err
	}
	delegationInfos := make(map[staking.Address]*staking.DelegationInfo, len(delegations))
	for delAddr, del := range delegations {
		delAcct, err := q.state.Account(ctx, delAddr)
		if err != nil {
			return nil, err
		}
		delegationInfos[delAddr] = &staking.DelegationInfo{
			Delegation: *del,
			Pool:       delAcct.Escrow.Active,
		}
	}
	return delegationInfos, nil
}

// DelegationsTo implements staking.Query.
func (q *Query) DelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return q.state.DelegationsTo(ctx, addr)
}

// DebondingDelegationsFor implements staking.Query.
func (q *Query) DebondingDelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return q.state.DebondingDelegationsFor(ctx, addr)
}

// DebondingDelegationInfosFor implements staking.Query.
func (q *Query) DebondingDelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegationInfo, error) {
	delegations, err := q.state.DebondingDelegationsFor(ctx, addr)
	if err != nil {
		return nil, err
	}
	delegationInfos := make(map[staking.Address][]*staking.DebondingDelegationInfo, len(delegations))
	for delAddr, delList := range delegations {
		delAcct, err := q.state.Account(ctx, delAddr)
		if err != nil {
			return nil, err
		}
		delInfoList := make([]*staking.DebondingDelegationInfo, len(delList))
		for i, del := range delList {
			delInfoList[i] = &staking.DebondingDelegationInfo{
				DebondingDelegation: *del,
				Pool:                delAcct.Escrow.Debonding,
			}
		}
		delegationInfos[delAddr] = delInfoList
	}
	return delegationInfos, nil
}

// DebondingDelegationsTo implements staking.Query.
func (q *Query) DebondingDelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return q.state.DebondingDelegationsTo(ctx, addr)
}

// ConsensusParameters implements staking.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*staking.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
