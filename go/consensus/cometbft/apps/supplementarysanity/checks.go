package supplementarysanity

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func checkEpochTime(_ *abciAPI.Context, now beacon.EpochTime) error {
	if now == beacon.EpochInvalid {
		return fmt.Errorf("current epoch is invalid")
	}

	// nothing to check yet
	return nil
}

func checkRegistry(ctx *abciAPI.Context, now beacon.EpochTime) error {
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
	runtimes, err := st.Runtimes(ctx)
	if err != nil {
		return fmt.Errorf("Runtimes(): %w", err)
	}
	suspendedRuntimes, err := st.SuspendedRuntimes(ctx)
	if err != nil {
		return fmt.Errorf("SuspendedRuntimes: %w", err)
	}

	runtimeLookup, err := registry.SanityCheckRuntimes(logger, params, runtimes, suspendedRuntimes, false, now)
	if err != nil {
		return fmt.Errorf("SanityCheckRuntimes: %w", err)
	}

	// Check nodes.
	signedNodes, err := st.SignedNodes(ctx)
	if err != nil {
		return fmt.Errorf("SignedNodes: %w", err)
	}
	_, err = registry.SanityCheckNodes(logger, params, signedNodes, seenEntities, runtimeLookup, false, now, ctx.Now(), uint64(ctx.LastHeight()))
	if err != nil {
		return fmt.Errorf("SanityCheckNodes: %w", err)
	}

	return nil
}

func checkRootHash(ctx *abciAPI.Context, _ beacon.EpochTime) error {
	st := roothashState.NewMutableState(ctx.State())

	// Check blocks.
	runtimes, err := st.RuntimeStates(ctx)
	if err != nil {
		return fmt.Errorf("Runtimes(): %w", err)
	}

	blocks := make(map[common.Namespace]*block.Block)
	runtimesByID := make(map[common.Namespace]*roothash.RuntimeState)
	for _, rt := range runtimes {
		blocks[rt.Runtime.ID] = rt.LastBlock
		runtimesByID[rt.Runtime.ID] = rt
	}
	err = roothash.SanityCheckBlocks(blocks)
	if err != nil {
		return fmt.Errorf("SanityCheckBlocks: %w", err)
	}

	// Check runtime states.
	for id, rtState := range runtimesByID {
		switch rtState.Suspended {
		case true:
			if rtState.Committee != nil {
				return fmt.Errorf("suspended runtime %s should not have a committee", id)
			}
			if rtState.CommitmentPool != nil {
				return fmt.Errorf("suspended runtime %s should not gather executor commitments", id)
			}
			if rtState.LivenessStatistics != nil {
				return fmt.Errorf("suspended runtime %s should not gather statistics", id)
			}
			if rtState.NextTimeout != roothash.TimeoutNever {
				return fmt.Errorf("round timeout for suspended runtime %s should not be scheduled at %d", id, rtState.NextTimeout)
			}
		case false:
			if rtState.Committee == nil {
				return fmt.Errorf("non-suspended runtime %s should have a committee", id)
			}
			if rtState.CommitmentPool == nil {
				return fmt.Errorf("non-suspended runtime %s should gather executor commitments", id)
			}
		}
	}

	// Make sure that runtime timeout state is consistent with actual timeouts.
	runtimeIDs, heights, err := st.RuntimesWithRoundTimeoutsAny(ctx)
	if err != nil {
		return fmt.Errorf("RuntimesWithRoundTimeoutsAny: %w", err)
	}
	for i, id := range runtimeIDs {
		height := heights[i]
		if height < ctx.CurrentHeight() {
			return fmt.Errorf("round timeout for runtime %s was scheduled at %d but did not trigger", id, height)
		}
		if rtState := runtimesByID[id]; rtState.NextTimeout != height {
			return fmt.Errorf("round timeout for runtime %s was scheduled at %d instead of %d", id, height, rtState.NextTimeout)
		}
		delete(runtimesByID, id)
	}
	for id, rtState := range runtimesByID {
		if rtState.NextTimeout != roothash.TimeoutNever {
			return fmt.Errorf("round timeout for runtime %s is not scheduled at %d", id, rtState.NextTimeout)
		}
	}

	// nothing to check yet
	return nil
}

func checkStaking(ctx *abciAPI.Context, now beacon.EpochTime) error { //nolint: gocyclo
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
	addresses, err := st.Addresses(ctx)
	if err != nil {
		return fmt.Errorf("Addresses(): %w", err)
	}
	addressesWithCommissionSchedule := make(map[staking.Address]bool)
	var acct *staking.Account
	for _, addr := range addresses {
		acct, err = st.Account(ctx, addr)
		if err != nil {
			return fmt.Errorf("Account(): %w", err)
		}
		err = staking.SanityCheckAccount(&total, parameters, now, addr, acct, totalSupply)
		if err != nil {
			return fmt.Errorf("SanityCheckAccount %s: %w", addr, err)
		}
		if !acct.Escrow.CommissionSchedule.IsEmpty() {
			addressesWithCommissionSchedule[addr] = true
		}
	}

	totalFees, err := st.LastBlockFees(ctx)
	if err != nil {
		return fmt.Errorf("LastBlockFees: %w", err)
	}
	if !totalFees.IsValid() {
		return fmt.Errorf("common pool %v is invalid", commonPool)
	}

	governanceDeposits, err := st.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("GovernanceDeposits: %w", err)
	}
	if !governanceDeposits.IsValid() {
		return fmt.Errorf("governance deposits %v is invalid", governanceDeposits)
	}

	_ = total.Add(governanceDeposits)
	_ = total.Add(commonPool)
	_ = total.Add(totalFees)
	if total.Cmp(totalSupply) != 0 {
		return fmt.Errorf(
			"balances in accounts plus governance deposits (%s), plus common pool (%s), plus last block fees (%s), does not add up to total supply (%s)",
			governanceDeposits.String(), commonPool.String(), totalFees.String(), totalSupply.String(),
		)
	}

	// Ensure CommissionScheduleAddresses response matches actual addresses with commission schedule.
	commissionAddresses, err := st.CommissionScheduleAddresses(ctx)
	if err != nil {
		return fmt.Errorf("CommissionScheduleAddresses(): %w", err)
	}
	if l1, l2 := len(addressesWithCommissionSchedule), len(commissionAddresses); l1 != l2 {
		return fmt.Errorf("number of addresses with non-empty commission schedule (%d) doesn't match the number of addresses returned by CommissionScheduleAddresses (%d)",
			l1, l2)
	}
	seen := make(map[staking.Address]bool, len(commissionAddresses))
	for _, addr := range commissionAddresses {
		if _, ok := seen[addr]; ok {
			return fmt.Errorf("duplicate address in CommissionScheduleAddresses response (%s)", addr)
		}
		seen[addr] = true
		if _, ok := addressesWithCommissionSchedule[addr]; !ok {
			return fmt.Errorf("address without commission schedule (%s) in CommissionScheduleAddresses response", addr)
		}
	}

	// All shares of all delegations for a given account must add up to account's Escrow.Active.TotalShares.
	addressesDelegationsMap, err := st.Delegations(ctx)
	if err != nil {
		return fmt.Errorf("Delegations(): %w", err)
	}
	for address, delegations := range addressesDelegationsMap {
		acct, err = st.Account(ctx, address)
		if err != nil {
			return fmt.Errorf("Account() %s: %w", address, err)
		}
		if err = staking.SanityCheckDelegations(address, acct, delegations); err != nil {
			return err
		}
	}

	// All shares of all debonding delegations for a given account must add up to account's Escrow.Debonding.TotalShares.
	addressesDebondingDelegationsMap, err := st.DebondingDelegations(ctx)
	if err != nil {
		return fmt.Errorf("DebondingDelegations: %w", err)
	}
	for address, debondingDelegations := range addressesDebondingDelegationsMap {
		acct, err = st.Account(ctx, address)
		if err != nil {
			return fmt.Errorf("Account() %s: %w", address, err)
		}
		if err = staking.SanityCheckDebondingDelegations(address, acct, debondingDelegations); err != nil {
			return err
		}
	}

	// Check the above two invariants for each account as well.
	for _, addr := range addresses {
		acct, err = st.Account(ctx, addr)
		if err != nil {
			return fmt.Errorf("Account(): %w", err)
		}
		if err = staking.SanityCheckAccountShares(
			addr, acct, addressesDelegationsMap[addr],
			addressesDebondingDelegationsMap[addr],
		); err != nil {
			return err
		}
	}

	return nil
}

func checkKeyManager(ctx *abciAPI.Context, _ beacon.EpochTime) error {
	st := secretsState.NewMutableState(ctx.State())

	statuses, err := st.Statuses(ctx)
	if err != nil {
		return fmt.Errorf("Statuses(): %w", err)
	}
	err = secrets.SanityCheckStatuses(statuses)
	if err != nil {
		return fmt.Errorf("SanityCheckStatuses: %w", err)
	}

	return nil
}

func checkGovernance(ctx *abciAPI.Context, epoch beacon.EpochTime) error {
	st := governanceState.NewMutableState(ctx.State())
	stakingState := stakingState.NewMutableState(ctx.State())
	govDeposits, err := stakingState.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("GovernanceDeposits: %w", err)
	}

	params, err := st.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("ConsensusParameters: %w", err)
	}
	err = params.SanityCheck()
	if err != nil {
		return fmt.Errorf("SanityCheck ConsensusParameters: %w", err)
	}
	// Sanity check proposals.
	proposals, err := st.Proposals(ctx)
	if err != nil {
		return fmt.Errorf("Proposals(): %w", err)
	}
	err = governance.SanityCheckProposals(proposals, epoch, govDeposits)
	if err != nil {
		return fmt.Errorf("SanityCheck Proposals: %w", err)
	}
	// Sanity check votes.
	for _, p := range proposals {
		var votes []*governance.VoteEntry
		votes, err = st.Votes(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("Votes(): %w", err)
		}
		err = governance.SanityCheckVotes(p, votes)
		if err != nil {
			return fmt.Errorf("SanityCheckVotes: %w", err)
		}
	}
	// Sanity check pending upgrades.
	pendingUpgrades, err := st.PendingUpgrades(ctx)
	if err != nil {
		return fmt.Errorf("PendingUpgrades: %w", err)
	}
	err = governance.SanityCheckPendingUpgrades(pendingUpgrades, epoch, params)
	if err != nil {
		return fmt.Errorf("SanityCheck PendingUpgrades: %w", err)
	}

	return nil
}

func checkScheduler(*abciAPI.Context, beacon.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkBeacon(*abciAPI.Context, beacon.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkConsensus(*abciAPI.Context, beacon.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkHalt(*abciAPI.Context, beacon.EpochTime) error {
	// nothing to check yet
	return nil
}

func checkStakeClaims(ctx *abciAPI.Context, _ beacon.EpochTime) error {
	regSt := registryState.NewMutableState(ctx.State())
	stakingSt := stakingState.NewMutableState(ctx.State())
	churpSt := churpState.NewMutableState(ctx.State())

	params, err := stakingSt.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get staking consensus parameters: %w", err)
	}

	// Skip checks if stake is being bypassed.
	if params.DebugBypassStake {
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
	accounts := make(map[staking.Address]*staking.Account)
	addresses, err := stakingSt.Addresses(ctx)
	if err != nil {
		return fmt.Errorf("failed to get staking addresses: %w", err)
	}
	for _, addr := range addresses {
		accounts[addr], err = stakingSt.Account(ctx, addr)
		if err != nil {
			return fmt.Errorf("failed to get staking account %s: %w", addr, err)
		}
	}
	// Get key manager churp statuses.
	churps, err := churpSt.AllStatuses(ctx)
	if err != nil {
		return fmt.Errorf("failed to get churp statuses: %w", err)
	}

	// Generate escrows.
	escrows := make(map[staking.Address]*staking.EscrowAccount)
	if err = churp.AddStakeClaims(churps, runtimes, escrows); err != nil {
		return err
	}
	if err = registry.AddStakeClaims(entities, nodes, runtimes, runtimes, escrows); err != nil {
		return err
	}

	return staking.SanityCheckStake(accounts, escrows, params.Thresholds, false)
}
