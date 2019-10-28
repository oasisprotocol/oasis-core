package staking

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
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
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := stakingState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx := abci.FromCtx(ctx); abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}
	return &stakingQuerier{state}, nil
}

type stakingQuerier struct {
	state *stakingState.ImmutableState
}

func (sq *stakingQuerier) TotalSupply(ctx context.Context) (*staking.Quantity, error) {
	return sq.state.TotalSupply()
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
	return sq.state.DebondingInterval()
}

func (sq *stakingQuerier) Accounts(ctx context.Context) ([]signature.PublicKey, error) {
	return sq.state.Accounts()
}

func (sq *stakingQuerier) AccountInfo(ctx context.Context, id signature.PublicKey) (*staking.Account, error) {
	return sq.state.Account(id), nil
}

func (sq *stakingQuerier) DebondingDelegations(ctx context.Context, id signature.PublicKey) (map[signature.MapKey][]*staking.DebondingDelegation, error) {
	return sq.state.DebondingDelegationsFor(id)
}

func (app *stakingApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
