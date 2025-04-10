package staking

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Query is the staking query interface.
type Query interface {
	TotalSupply(context.Context) (*quantity.Quantity, error)
	CommonPool(context.Context) (*quantity.Quantity, error)
	LastBlockFees(context.Context) (*quantity.Quantity, error)
	GovernanceDeposits(context.Context) (*quantity.Quantity, error)
	Threshold(context.Context, staking.ThresholdKind) (*quantity.Quantity, error)
	DebondingInterval(context.Context) (beacon.EpochTime, error)
	Addresses(context.Context) ([]staking.Address, error)
	CommissionScheduleAddresses(context.Context) ([]staking.Address, error)
	Account(context.Context, staking.Address) (*staking.Account, error)
	DelegationsFor(context.Context, staking.Address) (map[staking.Address]*staking.Delegation, error)
	DelegationInfosFor(context.Context, staking.Address) (map[staking.Address]*staking.DelegationInfo, error)
	DelegationsTo(context.Context, staking.Address) (map[staking.Address]*staking.Delegation, error)
	DebondingDelegationsFor(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error)
	DebondingDelegationInfosFor(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegationInfo, error)
	DebondingDelegationsTo(context.Context, staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error)
	Genesis(context.Context) (*staking.Genesis, error)
	ConsensusParameters(context.Context) (*staking.ConsensusParameters, error)
}

// QueryFactory is the staking query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the staking query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &stakingQuerier{
		state: stakingState.NewImmutableState(state),
	}, nil
}

type stakingQuerier struct {
	state *stakingState.ImmutableState
}

func (q *stakingQuerier) TotalSupply(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.TotalSupply(ctx)
}

func (q *stakingQuerier) CommonPool(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.CommonPool(ctx)
}

func (q *stakingQuerier) LastBlockFees(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.LastBlockFees(ctx)
}

func (q *stakingQuerier) GovernanceDeposits(ctx context.Context) (*quantity.Quantity, error) {
	return q.state.GovernanceDeposits(ctx)
}

func (q *stakingQuerier) Threshold(ctx context.Context, kind staking.ThresholdKind) (*quantity.Quantity, error) {
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

func (q *stakingQuerier) DebondingInterval(ctx context.Context) (beacon.EpochTime, error) {
	return q.state.DebondingInterval(ctx)
}

func (q *stakingQuerier) Addresses(ctx context.Context) ([]staking.Address, error) {
	return q.state.Addresses(ctx)
}

func (q *stakingQuerier) CommissionScheduleAddresses(ctx context.Context) ([]staking.Address, error) {
	return q.state.CommissionScheduleAddresses(ctx)
}

func (q *stakingQuerier) Account(ctx context.Context, addr staking.Address) (*staking.Account, error) {
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

func (q *stakingQuerier) DelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return q.state.DelegationsFor(ctx, addr)
}

func (q *stakingQuerier) DelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.DelegationInfo, error) {
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

func (q *stakingQuerier) DelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return q.state.DelegationsTo(ctx, addr)
}

func (q *stakingQuerier) DebondingDelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return q.state.DebondingDelegationsFor(ctx, addr)
}

func (q *stakingQuerier) DebondingDelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegationInfo, error) {
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

func (q *stakingQuerier) DebondingDelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return q.state.DebondingDelegationsTo(ctx, addr)
}

func (q *stakingQuerier) ConsensusParameters(ctx context.Context) (*staking.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

func (app *Application) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
