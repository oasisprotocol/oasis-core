package supplementarysanity

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	keymanagerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func checkEpochTime(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	if now == epochtime.EpochInvalid {
		return fmt.Errorf("current epoch is invalid")
	}

	// nothing to check yet
	return nil
}

func checkRegistry(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	st := registryState.NewMutableState(ctx.State())

	params, err := st.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	// Check entities.
	signedEntities, err := st.SignedEntities(ctx)
	if err != nil {
		return fmt.Errorf("SignedEntities: %w", err)
	}
	seenEntities, err := registry.SanityCheckEntities(logger, signedEntities)
	if err != nil {
		return fmt.Errorf("SanityCheckEntities: %w", err)
	}

	// Check runtimes.
	signedRuntimes, err := st.SignedRuntimes(ctx)
	if err != nil {
		return fmt.Errorf("AllSignedRuntimes: %w", err)
	}
	suspendedRuntimes, err := st.SuspendedRuntimes(ctx)
	if err != nil {
		return fmt.Errorf("SuspendedRuntimes: %w", err)
	}

	runtimeLookup, err := registry.SanityCheckRuntimes(logger, params, signedRuntimes, suspendedRuntimes, false)
	if err != nil {
		return fmt.Errorf("SanityCheckRuntimes: %w", err)
	}

	// Check nodes.
	signedNodes, err := st.SignedNodes(ctx)
	if err != nil {
		return fmt.Errorf("SignedNodes: %w", err)
	}
	_, err = registry.SanityCheckNodes(logger, params, signedNodes, seenEntities, runtimeLookup, false, now)
	if err != nil {
		return fmt.Errorf("SanityCheckNodes: %w", err)
	}

	return nil
}

func checkRootHash(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	st := roothashState.NewMutableState(ctx.State())

	// Check blocks.
	runtimes, err := st.Runtimes(ctx)
	if err != nil {
		return fmt.Errorf("Runtimes: %w", err)
	}

	blocks := make(map[common.Namespace]*block.Block)
	for _, rt := range runtimes {
		blocks[rt.Runtime.ID] = rt.CurrentBlock
	}
	err = roothash.SanityCheckBlocks(blocks)
	if err != nil {
		return fmt.Errorf("SanityCheckBlocks: %w", err)
	}

	// nothing to check yet
	return nil
}

func checkStaking(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	st := stakingState.NewMutableState(ctx.State())

	parameters, err := st.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}

	totalSupply, err := st.TotalSupply(ctx)
	if err != nil {
		return fmt.Errorf("TotalSupply: %w", err)
	}
	if !totalSupply.IsValid() {
		return fmt.Errorf("total supply %v is invalid", totalSupply)
	}

	commonPool, err := st.CommonPool(ctx)
	if err != nil {
		return fmt.Errorf("CommonPool: %w", err)
	}
	if !commonPool.IsValid() {
		return fmt.Errorf("common pool %v is invalid", commonPool)
	}

	// Check if the total supply adds up (common pool + all balances in the ledger).
	// Check all commission schedules.
	var total quantity.Quantity
	accounts, err := st.Accounts(ctx)
	if err != nil {
		return fmt.Errorf("Accounts: %w", err)
	}
	var acct *staking.Account
	for _, id := range accounts {
		acct, err = st.Account(ctx, id)
		if err != nil {
			return fmt.Errorf("Account: %w", err)
		}
		err = staking.SanityCheckAccount(&total, parameters, now, id, acct)
		if err != nil {
			return fmt.Errorf("SanityCheckAccount %s: %w", id, err)
		}
	}

	totalFees, err := st.LastBlockFees(ctx)
	if err != nil {
		return fmt.Errorf("LastBlockFees: %w", err)
	}
	if !totalFees.IsValid() {
		return fmt.Errorf("common pool %v is invalid", commonPool)
	}

	_ = total.Add(commonPool)
	_ = total.Add(totalFees)
	if total.Cmp(totalSupply) != 0 {
		return fmt.Errorf("balances in accounts plus common pool (%s) plus last block fees (%s) does not add up to total supply (%s)", total.String(), totalFees.String(), totalSupply.String())
	}

	// All shares of all delegations for a given account must add up to account's Escrow.Active.TotalShares.
	delegationses, err := st.Delegations(ctx)
	if err != nil {
		return fmt.Errorf("Delegations: %w", err)
	}
	for id, delegations := range delegationses {
		acct, err = st.Account(ctx, id)
		if err != nil {
			return fmt.Errorf("Account: %w", err)
		}
		if err = staking.SanityCheckDelegations(id, acct, delegations); err != nil {
			return err
		}
	}

	// All shares of all debonding delegations for a given account must add up to account's Escrow.Debonding.TotalShares.
	debondingDelegationses, err := st.DebondingDelegations(ctx)
	if err != nil {
		return fmt.Errorf("DebondingDelegations: %w", err)
	}
	for id, debondingDelegations := range debondingDelegationses {
		acct, err = st.Account(ctx, id)
		if err != nil {
			return fmt.Errorf("Account: %w", err)
		}
		if err = staking.SanityCheckDebondingDelegations(id, acct, debondingDelegations); err != nil {
			return err
		}
	}

	// Check the above two invariants for each account as well.
	for _, id := range accounts {
		acct, err = st.Account(ctx, id)
		if err != nil {
			return fmt.Errorf("Account: %w", err)
		}
		if err = staking.SanityCheckAccountShares(id, acct, delegationses[id], debondingDelegationses[id]); err != nil {
			return err
		}
	}

	return nil
}

func checkKeyManager(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	st := keymanagerState.NewMutableState(ctx.State())

	statuses, err := st.Statuses(ctx)
	if err != nil {
		return fmt.Errorf("Statuses: %w", err)
	}
	err = keymanager.SanityCheckStatuses(statuses)
	if err != nil {
		return fmt.Errorf("SanityCheckStatuses: %w", err)
	}

	return nil
}

func checkScheduler(*abciAPI.Context, epochtime.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkBeacon(*abciAPI.Context, epochtime.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkConsensus(*abciAPI.Context, epochtime.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkHalt(*abciAPI.Context, epochtime.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkStakeClaims(ctx *abciAPI.Context, now epochtime.EpochTime) error {
	regSt := registryState.NewMutableState(ctx.State())
	stakingSt := stakingState.NewMutableState(ctx.State())

	regParams, err := regSt.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get registry consensus parameters: %w", err)
	}
	stakingParams, err := stakingSt.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get staking consensus parameters: %w", err)
	}

	// Skip checks if stake is being bypassed.
	if regParams.DebugBypassStake {
		return nil
	}

	// Get registered entities.
	entities, err := regSt.Entities(ctx)
	if err != nil {
		return fmt.Errorf("failed to get entities: %w", err)
	}
	// Get registered nodes.
	nodes, err := regSt.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get node registrations: %w", err)
	}
	// Get registered runtimes.
	runtimes, err := regSt.AllRuntimes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get runtime registrations: %w", err)
	}
	// Get staking accounts.
	accounts := make(map[signature.PublicKey]*staking.Account)
	accountIDs, err := stakingSt.Accounts(ctx)
	if err != nil {
		return fmt.Errorf("failed to get staking accounts: %w", err)
	}
	for _, id := range accountIDs {
		accounts[id], err = stakingSt.Account(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to get staking account with id %s: %w", id, err)
		}
	}

	return registry.SanityCheckStake(entities, accounts, nodes, runtimes, stakingParams.Thresholds, false)
}
