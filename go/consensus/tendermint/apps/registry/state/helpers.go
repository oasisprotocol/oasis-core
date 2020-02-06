package state

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// EnsureSufficientRuntimeStake checks that the given entity has sufficient stake to operate a
// given runtime (with separate thresholds for compute and key manager runtimes).
func EnsureSufficientRuntimeStake(ctx *abci.Context, rt *registry.Runtime) error {
	thresholds := []staking.ThresholdKind{
		staking.KindEntity,
	}
	switch rt.Kind {
	case registry.KindCompute:
		thresholds = append(thresholds, staking.KindRuntimeCompute)
	case registry.KindKeyManager:
		thresholds = append(thresholds, staking.KindRuntimeKeyManager)
	default:
		ctx.Logger().Error("RegisterRuntime: unknown runtime kind",
			"runtime_id", rt.ID,
			"kind", rt.Kind,
		)
		return fmt.Errorf("registry: unknown runtime kind (%d)", rt.Kind)
	}
	return stakingState.EnsureSufficientStake(ctx, rt.EntityID, thresholds)
}
