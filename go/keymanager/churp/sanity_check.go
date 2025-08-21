package churp

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// AddStakeClaims adds stake claims for the given schemes.
func AddStakeClaims(statuses []*Status, runtimes []*registry.Runtime, escrows map[staking.Address]*staking.EscrowAccount) error {
	churps := make(map[common.Namespace][]uint8)
	for _, status := range statuses {
		churps[status.RuntimeID] = append(churps[status.RuntimeID], status.ID)
	}

	thresholds := StakeThresholds()

	for _, rt := range runtimes {
		ids, ok := churps[rt.ID]
		if !ok {
			continue
		}

		addr, ok := rt.StakingAddress()
		if !ok {
			continue
		}
		escrow, ok := escrows[*addr]
		if !ok {
			escrow = &staking.EscrowAccount{}
			escrows[*addr] = escrow
		}

		for _, id := range ids {
			escrow.StakeAccumulator.AddClaimUnchecked(StakeClaim(rt.ID, id), thresholds)
		}
		delete(churps, rt.ID)
	}

	if len(churps) > 0 {
		return fmt.Errorf("failed to add all stake claims")
	}

	return nil
}
