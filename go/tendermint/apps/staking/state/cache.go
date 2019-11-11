package state

import (
	"fmt"
	"math/big"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func EnsureSufficientStake(ctx *abci.Context, id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	sc, err := NewStakeCache(ctx)
	if err != nil {
		return err
	}
	return sc.EnsureSufficientStake(id, thresholds)
}

// StakeCache is a lookup cache for escrow balances and thresholds that
// can be used in lieu of repeated queries to `EnsureSufficientStake` at a
// given height.  This should be favored when repeated queries are going to
// be made.
type StakeCache struct {
	ctx *abci.Context

	thresholds map[staking.ThresholdKind]quantity.Quantity
	balances   map[signature.MapKey]*quantity.Quantity

	lowestNonZeroThreshold quantity.Quantity
}

// EnsureNodeRegistrationStake ensures the account owned by id has sufficient
// stake to support the number of nodes, under the assumption that all
// nodes will be elected with the lowest non-zero threshold.  This routine
// ignores what roles the nodes actually are registering for as it is
// intended to be a cheap check to prevent node registration Tx spam.
func (sc *StakeCache) EnsureNodeRegistrationStake(id signature.PublicKey, n int) error {
	var newNumNodes quantity.Quantity
	if err := newNumNodes.FromBigInt(big.NewInt(int64(n))); err != nil {
		return fmt.Errorf("staking/tendermint: failed to create node multiplier: %w", err)
	}

	targetThreshold := sc.lowestNonZeroThreshold.Clone()
	if err := targetThreshold.Mul(&newNumNodes); err != nil {
		return fmt.Errorf("staking/tendermint: failed to derive node target threshold: %w", err)
	}

	escrowBalance := sc.GetEscrowBalance(id)
	if escrowBalance.Cmp(targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func (sc *StakeCache) EnsureSufficientStake(id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	var targetThreshold quantity.Quantity
	for _, v := range thresholds {
		qty := sc.thresholds[v]
		if err := targetThreshold.Add(&qty); err != nil {
			return fmt.Errorf("staking/tendermint: failed to accumulate threshold: %w", err)
		}
	}

	escrowBalance := sc.GetEscrowBalance(id)
	if escrowBalance.Cmp(&targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// GetEscrowBalance returns the escrow balance of the account owned by id.
func (sc *StakeCache) GetEscrowBalance(id signature.PublicKey) quantity.Quantity {
	escrowBalance := sc.balances[id.ToMapKey()]
	if escrowBalance == nil {
		state := NewMutableState(sc.ctx.State())
		escrowBalance = state.EscrowBalance(id)
		sc.balances[id.ToMapKey()] = escrowBalance
	}

	ret := escrowBalance.Clone()
	return *ret
}

// NewStakeCache creates a new staking lookup cache.
func NewStakeCache(ctx *abci.Context) (*StakeCache, error) {
	state := NewMutableState(ctx.State())

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, fmt.Errorf("staking/tendermint: failed to query thresholds: %w", err)
	}

	lowestNonZeroThreshold := quantity.NewQuantity()
	for _, v := range thresholds {
		if lowestNonZeroThreshold.IsZero() {
			lowestNonZeroThreshold = v.Clone()
		} else if !v.IsZero() && lowestNonZeroThreshold.Cmp(&v) == 1 {
			lowestNonZeroThreshold = v.Clone()
		}
	}

	return &StakeCache{
		ctx:                    ctx,
		thresholds:             thresholds,
		balances:               make(map[signature.MapKey]*quantity.Quantity),
		lowestNonZeroThreshold: *lowestNonZeroThreshold,
	}, nil
}
