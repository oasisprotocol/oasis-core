package state

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
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

	thresholds map[staking.ThresholdKind]staking.Quantity
	balances   map[signature.MapKey]*staking.Quantity
}

// EnsureSufficientStake ensures that the account owned by id has sufficient
// stake to meet the sum of the thresholds specified.  The thresholds vector
// can have multiple instances of the same threshold kind specified, in which
// case it will be factored in repeatedly.
func (sc *StakeCache) EnsureSufficientStake(id signature.PublicKey, thresholds []staking.ThresholdKind) error {
	escrowBalance := sc.balances[id.ToMapKey()]
	if escrowBalance == nil {
		state := NewMutableState(sc.ctx.State())
		escrowBalance = state.EscrowBalance(id)
		sc.balances[id.ToMapKey()] = escrowBalance
	}

	var targetThreshold staking.Quantity
	for _, v := range thresholds {
		qty := sc.thresholds[v]
		if err := targetThreshold.Add(&qty); err != nil {
			return fmt.Errorf("staking/tendermint: failed to accumulate threshold: %w", err)
		}
	}

	if escrowBalance.Cmp(&targetThreshold) < 0 {
		return staking.ErrInsufficientStake
	}

	return nil
}

// NewStakeCache creates a new staking lookup cache.
func NewStakeCache(ctx *abci.Context) (*StakeCache, error) {
	state := NewMutableState(ctx.State())

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, fmt.Errorf("staking/tendermint: failed to query thresholds: %w", err)
	}

	return &StakeCache{
		ctx:        ctx,
		thresholds: thresholds,
		balances:   make(map[signature.MapKey]*staking.Quantity),
	}, nil
}
