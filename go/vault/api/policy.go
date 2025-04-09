package api

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

// AddressState is the state stored for the given address.
type AddressState struct {
	// WithdrawPolicy is the active withdraw policy.
	WithdrawPolicy WithdrawPolicy `json:"withdraw_policy"`

	// CurrentBucket specifies the interval we are currently doing accounting for.
	CurrentBucket uint64 `json:"bucket"`
	// CurrentAmount specifies the amount already withdrawn in the current interval.
	CurrentAmount quantity.Quantity `json:"amount"`
}

// UpdateWithdrawPolicy updates the withdraw policy to a new policy together with any internal
// accounting adjustments.
func (as *AddressState) UpdateWithdrawPolicy(newPolicy *WithdrawPolicy) {
	if as.WithdrawPolicy.LimitInterval != newPolicy.LimitInterval {
		as.CurrentBucket = 0
		as.CurrentAmount = *quantity.NewQuantity()
	}
	as.WithdrawPolicy = *newPolicy
}

// AuthorizeWithdrawal performs withdrawal authorization. In case withdrawal is allowed, the state
// is also updated to reflect the additional withdrawal.
func (as *AddressState) AuthorizeWithdrawal(height int64, amount *quantity.Quantity) bool {
	if amount.IsZero() {
		return true
	}
	if as.WithdrawPolicy.IsDisabled() {
		return false
	}

	// If current bucket is different than the last recorded bucket, reset current amount.
	currentAmount := &as.CurrentAmount
	currentBucket := uint64(height) / as.WithdrawPolicy.LimitInterval
	if as.CurrentBucket != currentBucket {
		currentAmount = quantity.NewQuantity()
	}

	// Compute how much we can withdraw.
	wanted := amount.Clone()
	if err := wanted.Add(currentAmount); err != nil {
		return false
	}
	if wanted.Cmp(&as.WithdrawPolicy.LimitAmount) > 0 {
		return false
	}

	// Update state and authorize withdrawal.
	as.CurrentBucket = currentBucket
	as.CurrentAmount = *wanted
	return true
}

// WithdrawPolicy is the per-address withdraw policy.
type WithdrawPolicy struct {
	// LimitAmount is the maximum amount of tokens that may be withdrawn in the given interval.
	LimitAmount quantity.Quantity `json:"limit_amount"`
	// LimitInterval is the interval (in blocks) when the limit amount resets.
	LimitInterval uint64 `json:"limit_interval"`
}

// IsDisabled returns true iff the policy is disabled and no withdrawal is allowed.
func (wp *WithdrawPolicy) IsDisabled() bool {
	return wp.LimitAmount.IsZero() || wp.LimitInterval == 0
}

// Validate validates the withdrawal policy.
func (wp *WithdrawPolicy) Validate() error {
	return nil
}

// PrettyPrint writes a pretty-printed representation of WithdrawPolicy to the given writer.
func (wp WithdrawPolicy) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sLimit: ", prefix)
	switch wp.IsDisabled() {
	case true:
		fmt.Fprintf(w, "not allowed\n")
	case false:
		token.PrettyPrintAmount(ctx, wp.LimitAmount, w)
		fmt.Fprintf(w, " / %d block(s)\n", wp.LimitInterval)
	}
}

// PrettyType returns a representation of WithdrawPolicy that can be used for pretty printing.
func (wp WithdrawPolicy) PrettyType() (any, error) {
	return wp, nil
}
