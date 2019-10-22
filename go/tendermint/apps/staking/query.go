package staking

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// ErrInvalidThreshold is the error returned when an invalid threshold kind
// is specified in a query.
var ErrInvalidThreshold = errors.New("staking: invalid threshold")

// Query is the staking query interface.
type Query interface {
	TotalSupply(context.Context) (*staking.Quantity, error)
	CommonPool(context.Context) (*staking.Quantity, error)
	Threshold(context.Context, staking.ThresholdKind) (*staking.Quantity, error)
	DebondingInterval(context.Context) (uint64, error)
	Accounts(context.Context) ([]signature.PublicKey, error)
	AccountInfo(context.Context, signature.PublicKey) (*staking.Account, error)
	DebondingDelegations(context.Context, signature.PublicKey) (map[signature.MapKey][]*staking.DebondingDelegation, error)
	Genesis(context.Context) (*staking.Genesis, error)
}

// QueryFactory is the staking query factory.
type QueryFactory struct {
	app *stakingApplication
}

// QueryAt returns the staking query interface for a specific height.
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &stakingQuerier{state}, nil
}

type stakingQuerier struct {
	state *immutableState
}

func (sq *stakingQuerier) TotalSupply(ctx context.Context) (*staking.Quantity, error) {
	return sq.state.totalSupply()
}

func (sq *stakingQuerier) CommonPool(ctx context.Context) (*staking.Quantity, error) {
	return sq.state.CommonPool()
}

func (sq *stakingQuerier) Threshold(ctx context.Context, kind staking.ThresholdKind) (*staking.Quantity, error) {
	thresholds, err := sq.state.Thresholds()
	if err != nil {
		return nil, err
	}

	threshold, ok := thresholds[kind]
	if !ok {
		return nil, ErrInvalidThreshold
	}
	return &threshold, nil
}

func (sq *stakingQuerier) DebondingInterval(ctx context.Context) (uint64, error) {
	return sq.state.debondingInterval()
}

func (sq *stakingQuerier) Accounts(ctx context.Context) ([]signature.PublicKey, error) {
	return sq.state.accounts()
}

func (sq *stakingQuerier) AccountInfo(ctx context.Context, id signature.PublicKey) (*staking.Account, error) {
	return sq.state.account(id), nil
}

func (sq *stakingQuerier) DebondingDelegations(ctx context.Context, id signature.PublicKey) (map[signature.MapKey][]*staking.DebondingDelegation, error) {
	return sq.state.debondingDelegationsFor(id)
}

func (app *stakingApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
