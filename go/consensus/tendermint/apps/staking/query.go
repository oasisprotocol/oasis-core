package staking

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
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
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := stakingState.NewImmutableState(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}
	return &stakingQuerier{state}, nil
}

type stakingQuerier struct {
	state *stakingState.ImmutableState
}

func (sq *stakingQuerier) TotalSupply(ctx context.Context) (*quantity.Quantity, error) {
	return sq.state.TotalSupply(ctx)
}

func (sq *stakingQuerier) CommonPool(ctx context.Context) (*quantity.Quantity, error) {
	return sq.state.CommonPool(ctx)
}

func (sq *stakingQuerier) LastBlockFees(ctx context.Context) (*quantity.Quantity, error) {
	return sq.state.LastBlockFees(ctx)
}

func (sq *stakingQuerier) GovernanceDeposits(ctx context.Context) (*quantity.Quantity, error) {
	return sq.state.GovernanceDeposits(ctx)
}

func (sq *stakingQuerier) Threshold(ctx context.Context, kind staking.ThresholdKind) (*quantity.Quantity, error) {
	thresholds, err := sq.state.Thresholds(ctx)
	if err != nil {
		return nil, err
	}

	threshold, ok := thresholds[kind]
	if !ok {
		return nil, staking.ErrInvalidThreshold
	}
	return &threshold, nil
}

func (sq *stakingQuerier) DebondingInterval(ctx context.Context) (beacon.EpochTime, error) {
	return sq.state.DebondingInterval(ctx)
}

func (sq *stakingQuerier) Addresses(ctx context.Context) ([]staking.Address, error) {
	return sq.state.Addresses(ctx)
}

func (sq *stakingQuerier) Account(ctx context.Context, addr staking.Address) (*staking.Account, error) {
	switch {
	case addr.Equal(staking.CommonPoolAddress):
		cp, err := sq.state.CommonPool(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *cp,
			},
		}, nil
	case addr.Equal(staking.FeeAccumulatorAddress):
		fa, err := sq.state.LastBlockFees(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *fa,
			},
		}, nil
	case addr.Equal(staking.GovernanceDepositsAddress):
		gd, err := sq.state.GovernanceDeposits(ctx)
		if err != nil {
			return nil, err
		}
		return &staking.Account{
			General: staking.GeneralAccount{
				Balance: *gd,
			},
		}, nil

	default:
		return sq.state.Account(ctx, addr)
	}
}

func (sq *stakingQuerier) DelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return sq.state.DelegationsFor(ctx, addr)
}

func (sq *stakingQuerier) DelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.DelegationInfo, error) {
	delegations, err := sq.state.DelegationsFor(ctx, addr)
	if err != nil {
		return nil, err
	}
	delegationInfos := make(map[staking.Address]*staking.DelegationInfo, len(delegations))
	for delAddr, del := range delegations {
		delAcct, err := sq.state.Account(ctx, delAddr)
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

func (sq *stakingQuerier) DelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address]*staking.Delegation, error) {
	return sq.state.DelegationsTo(ctx, addr)
}

func (sq *stakingQuerier) DebondingDelegationsFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return sq.state.DebondingDelegationsFor(ctx, addr)
}

func (sq *stakingQuerier) DebondingDelegationInfosFor(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegationInfo, error) {
	delegations, err := sq.state.DebondingDelegationsFor(ctx, addr)
	if err != nil {
		return nil, err
	}
	delegationInfos := make(map[staking.Address][]*staking.DebondingDelegationInfo, len(delegations))
	for delAddr, delList := range delegations {
		delAcct, err := sq.state.Account(ctx, delAddr)
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

func (sq *stakingQuerier) DebondingDelegationsTo(ctx context.Context, addr staking.Address) (map[staking.Address][]*staking.DebondingDelegation, error) {
	return sq.state.DebondingDelegationsTo(ctx, addr)
}

func (sq *stakingQuerier) ConsensusParameters(ctx context.Context) (*staking.ConsensusParameters, error) {
	return sq.state.ConsensusParameters(ctx)
}

func (app *stakingApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
