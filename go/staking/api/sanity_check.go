// Package api implements the staking backend API.
package api

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	// Thresholds.
	for kind := KindEntity; kind <= KindMax; kind++ {
		val, ok := p.Thresholds[kind]
		if !ok {
			return fmt.Errorf("threshold for kind '%s' not defined", kind)
		}
		if !val.IsValid() {
			return fmt.Errorf("threshold '%s' has invalid value", kind)
		}
	}

	// Fee splits.
	if !p.FeeSplitVote.IsValid() {
		return fmt.Errorf("fee split vote has invalid value")
	}
	if !p.FeeSplitPropose.IsValid() {
		return fmt.Errorf("fee split propose has invalid value")
	}
	if p.FeeSplitVote.IsZero() && p.FeeSplitPropose.IsZero() {
		return fmt.Errorf("fee split proportions are both zero")
	}

	return nil
}

// SanityCheckAccount examines an account's balances.
// Adds the balances to a running total `total`.
func SanityCheckAccount(total *quantity.Quantity, parameters *ConsensusParameters, now epochtime.EpochTime, id signature.PublicKey, acct *Account) error {
	if !acct.General.Balance.IsValid() {
		return fmt.Errorf("staking: sanity check failed: general balance is invalid for account with ID: %s", id)
	}
	if !acct.Escrow.Active.Balance.IsValid() {
		return fmt.Errorf("staking: sanity check failed: escrow active balance is invalid for account with ID: %s", id)
	}
	if !acct.Escrow.Debonding.Balance.IsValid() {
		return fmt.Errorf("staking: sanity check failed: escrow debonding balance is invalid for account with ID: %s", id)
	}

	_ = total.Add(&acct.General.Balance)
	_ = total.Add(&acct.Escrow.Active.Balance)
	_ = total.Add(&acct.Escrow.Debonding.Balance)

	commissionScheduleShallowCopy := acct.Escrow.CommissionSchedule
	if err := commissionScheduleShallowCopy.PruneAndValidateForGenesis(&parameters.CommissionScheduleRules, now); err != nil {
		return fmt.Errorf("staking: sanity check failed: commission schedule for account with ID %s is invalid: %+v", id, err)
	}

	return nil
}

// SanityCheckDelegations examines an account's delegations.
func SanityCheckDelegations(id signature.PublicKey, account *Account, delegations map[signature.PublicKey]*Delegation) error {
	var shares quantity.Quantity
	var numDelegations uint64
	for _, d := range delegations {
		_ = shares.Add(&d.Shares)
		numDelegations++
	}

	sharesExpected := account.Escrow.Active.TotalShares

	if shares.Cmp(&sharesExpected) != 0 {
		return fmt.Errorf("staking: sanity check failed: all shares of all delegations (%s) for account with ID: %s don't add up to account's total active shares in escrow (%s)", shares, id, sharesExpected)
	}

	// Account's Escrow.Active.Balance must be 0 if account has no delegations.
	if numDelegations == 0 {
		if !account.Escrow.Active.Balance.IsZero() {
			return fmt.Errorf("staking: sanity check failed: account with ID: %s has no delegations, but non-zero active escrow balance", id)
		}
	}

	return nil
}

// SanityCheckDebondingDelegations examines an account's debonding delegations.
func SanityCheckDebondingDelegations(id signature.PublicKey, account *Account, delegations map[signature.PublicKey][]*DebondingDelegation) error {
	var shares quantity.Quantity
	var numDebondingDelegations uint64
	for _, dels := range delegations {
		for _, d := range dels {
			_ = shares.Add(&d.Shares)
			numDebondingDelegations++
		}
	}

	sharesExpected := account.Escrow.Debonding.TotalShares

	if shares.Cmp(&sharesExpected) != 0 {
		return fmt.Errorf("staking: sanity check failed: all shares of all debonding delegations (%s) for account with ID: %s don't add up to account's total debonding shares in escrow (%s)", shares, id, sharesExpected)
	}

	// Account's Escrow.Debonding.Balance must be 0 if account has no debonding delegations.
	if numDebondingDelegations == 0 {
		if !account.Escrow.Debonding.Balance.IsZero() {
			return fmt.Errorf("staking: sanity check failed: account with ID: %s has no debonding delegations, but non-zero debonding escrow balance", id)
		}
	}
	return nil
}

// SanityCheckAccountShares examines an account's share pools.
func SanityCheckAccountShares(id signature.PublicKey, acct *Account, delegations map[signature.PublicKey]*Delegation, debondingDelegations map[signature.PublicKey][]*DebondingDelegation) error {
	// Count the delegations for this account and add up the total shares.
	var shares quantity.Quantity
	var numDelegations uint64
	for _, d := range delegations {
		_ = shares.Add(&d.Shares)
		numDelegations++
	}
	// Account's total active shares in escrow should match delegations.
	if shares.Cmp(&acct.Escrow.Active.TotalShares) != 0 {
		return fmt.Errorf("staking: sanity check failed: delegations (%s) for account with ID: %s don't match account's total active shares in escrow (%s)", shares, id, acct.Escrow.Active.TotalShares)
	}
	// If there are no delegations, the active escrow balance should be 0.
	if numDelegations == 0 {
		if !acct.Escrow.Active.Balance.IsZero() {
			return fmt.Errorf("staking: sanity check failed: account with ID: %s has no delegations, but non-zero active escrow balance", id)
		}
	}

	// Count the debonding delegations for this account and add up the total shares.
	var debondingShares quantity.Quantity
	var numDebondingDelegations uint64
	for _, dels := range debondingDelegations {
		for _, d := range dels {
			_ = debondingShares.Add(&d.Shares)
			numDebondingDelegations++
		}
	}
	// Account's total debonding shares in escrow should match debonding delegations.
	if debondingShares.Cmp(&acct.Escrow.Debonding.TotalShares) != 0 {
		return fmt.Errorf("staking: sanity check failed: debonding delegations (%s) for account with ID: %s don't match account's total debonding shares in escrow (%s)", debondingShares, id, acct.Escrow.Debonding.TotalShares)
	}
	// If there are no debonding delegations, the debonding escrow balance should be 0.
	if numDebondingDelegations == 0 {
		if !acct.Escrow.Debonding.Balance.IsZero() {
			return fmt.Errorf("staking: sanity check failed: account with ID: %s has no debonding delegations, but non-zero debonding escrow balance", id)
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(now epochtime.EpochTime) error { // nolint: gocyclo
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("staking: sanity check failed: %w", err)
	}

	if !g.TotalSupply.IsValid() {
		return fmt.Errorf("staking: sanity check failed: total supply is invalid")
	}

	if !g.CommonPool.IsValid() {
		return fmt.Errorf("staking: sanity check failed: common pool is invalid")
	}

	// Check if the total supply adds up (common pool + all balances in the ledger).
	// Check all commission schedules.
	var total quantity.Quantity
	for id, acct := range g.Ledger {
		err := SanityCheckAccount(&total, &g.Parameters, now, id, acct)
		if err != nil {
			return err
		}

		// Make sure that the stake accumulator is empty as otherwise it could be inconsistent with
		// what is registered in the genesis block.
		if len(acct.Escrow.StakeAccumulator.Claims) > 0 {
			return fmt.Errorf("staking: non-empty stake accumulator in genesis")
		}
	}
	_ = total.Add(&g.CommonPool)
	if total.Cmp(&g.TotalSupply) != 0 {
		return fmt.Errorf("staking: sanity check failed: balances in accounts plus common pool (%s) does not add up to total supply (%s)", total.String(), g.TotalSupply.String())
	}

	// All shares of all delegations for a given account must add up to account's Escrow.Active.TotalShares.
	for id, delegations := range g.Delegations {
		acct := g.Ledger[id]
		if acct == nil {
			return fmt.Errorf("staking: sanity check failed: delegation specified for a nonexisting account with ID: %v", id)
		}
		if err := SanityCheckDelegations(id, acct, delegations); err != nil {
			return err
		}
	}

	// All shares of all debonding delegations for a given account must add up to account's Escrow.Debonding.TotalShares.
	for id, delegations := range g.DebondingDelegations {
		acct := g.Ledger[id]
		if acct == nil {
			return fmt.Errorf("staking: sanity check failed: debonding delegation specified for a nonexisting account with ID: %v", id)
		}
		if err := SanityCheckDebondingDelegations(id, acct, delegations); err != nil {
			return err
		}
	}

	// Check the above two invariants for each account as well.
	for id, acct := range g.Ledger {
		if err := SanityCheckAccountShares(id, acct, g.Delegations[id], g.DebondingDelegations[id]); err != nil {
			return err
		}
	}

	return nil
}
