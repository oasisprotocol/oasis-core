package beacon

import (
	"context"
	"fmt"
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func onPVSSMisbehavior(
	ctx *abciAPI.Context,
	id signature.PublicKey,
	why staking.SlashReason,
) error {
	// Retrieve the penalty for the slashing reason.
	stakeState := stakingState.NewMutableState(ctx.State())
	st, err := stakeState.Slashing(ctx)
	if err != nil {
		ctx.Logger().Error("failed to get slashing table",
			"err", err,
		)
		return fmt.Errorf("beacon: failed to get slashing table: %w", err)
	}
	penalty := st[why]

	// Retrieve the node descriptor.
	regState := registryState.NewMutableState(ctx.State())
	node, err := regState.Node(ctx, id)
	if err != nil {
		// This should never happen since transactions only come from
		// nodes that are registered and selected as participants.
		ctx.Logger().Error("failed to get node by signature public key",
			"public_key", id,
			"err", err,
		)
		return fmt.Errorf("beacon: failed to get node by id %s: %w", id, err)
	}

	// Freeze the node if the penalty for this class of misbehavior
	// includes a non-zero freeze time.
	if penalty.FreezeInterval > 0 {
		var nodeStatus *registry.NodeStatus
		if nodeStatus, err = regState.NodeStatus(ctx, node.ID); err != nil {
			// This should never happen either, since all validators
			// should have valid node statuses.
			ctx.Logger().Warn("failed to get validator node status",
				"err", err,
				"node_id", node.ID,
			)
			return fmt.Errorf("beacon: failed to get node status: %w", err)
		}

		// If the node is already frozen, don't slash it again.
		//
		// XXX: Nodes that repeatedly attempt to misbehave *should* be
		// slashed into oblivion, but people will probably cry about it.
		if nodeStatus.FreezeEndTime > 0 {
			ctx.Logger().Warn("refusing to slash a frozen node",
				"node_id", node.ID,
			)
			return nil
		}

		var epoch beacon.EpochTime
		epoch, err = ctx.AppState().GetEpoch(context.Background(), ctx.BlockHeight()+1)
		if err != nil {
			return err
		}

		// Check for overflow.
		if math.MaxUint64-penalty.FreezeInterval < epoch {
			nodeStatus.FreezeEndTime = registry.FreezeForever
		} else {
			nodeStatus.FreezeEndTime = epoch + penalty.FreezeInterval
		}

		if err = regState.SetNodeStatus(ctx, node.ID, nodeStatus); err != nil {
			ctx.Logger().Error("failed to set validator node status",
				"err", err,
				"node_id", node.ID,
				"entity_id", node.EntityID,
			)
			return fmt.Errorf("beacon: failed to update node status: %w", err)
		}
	}

	// Slash runtime node entity.
	entityAddr := staking.NewAddress(node.EntityID)
	totalSlashed, err := stakeState.SlashEscrow(ctx, entityAddr, &penalty.Amount)
	if err != nil {
		return fmt.Errorf("beacon: error slashing account %s: %w", entityAddr, err)
	}

	ctx.Logger().Warn("slashed node for beacon misbehavior",
		"node_id", node.ID,
		"entity_id", node.EntityID,
		"reason", why,
		"total_slashed", totalSlashed,
	)

	return nil
}
