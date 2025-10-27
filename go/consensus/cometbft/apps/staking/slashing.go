package staking

import (
	"context"
	"encoding/hex"
	"math"

	cmtcrypto "github.com/cometbft/cometbft/crypto"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func onEvidenceByzantineConsensus(
	ctx *abciAPI.Context,
	reason staking.SlashReason,
	addr cmtcrypto.Address,
) error {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	// Resolve consensus node. Note that in order for this to work even in light
	// of node expirations, the node descriptor must be available for at least
	// the debonding period after expiration.
	node, err := regState.NodeByConsensusAddress(ctx, addr)
	if err != nil {
		ctx.Logger().Warn("failed to get validator node",
			"err", err,
			"address", hex.EncodeToString(addr),
		)
		return nil
	}

	nodeStatus, err := regState.NodeStatus(ctx, node.ID)
	if err != nil {
		ctx.Logger().Warn("failed to get validator node status",
			"err", err,
			"node_id", node.ID,
		)
		return nil
	}

	// Do not slash a frozen validator.
	if nodeStatus.IsFrozen() {
		ctx.Logger().Debug("not slashing frozen validator",
			"node_id", node.ID,
			"entity_id", node.EntityID,
			"freeze_end_time", nodeStatus.FreezeEndTime,
		)
		return nil
	}

	// Retrieve the slash procedure.
	st, err := stakeState.Slashing(ctx)
	if err != nil {
		ctx.Logger().Error("failed to get slashing table entry",
			"err", err,
		)
		return err
	}

	penalty := st[reason]

	// Freeze validator to prevent it being slashed again. This also prevents the
	// validator from being scheduled in the next epoch.
	if penalty.FreezeInterval > 0 {
		var epoch beacon.EpochTime
		// XXX: This should maybe use abciCtx and ctx.BlockHeight() + 1, but was
		// kept like this to avoid potential consensus breaking changes at this time.
		epoch, err = ctx.AppState().GetEpoch(context.Background(), ctx.LastHeight())
		if err != nil {
			return err
		}

		// Check for overflow.
		if math.MaxUint64-penalty.FreezeInterval < epoch {
			nodeStatus.Freeze(registry.FreezeForever)
		} else {
			nodeStatus.Freeze(epoch + penalty.FreezeInterval)
		}
	}

	// Slash validator.
	entityAddr := staking.NewAddress(node.EntityID)
	_, err = stakeState.SlashEscrow(ctx, entityAddr, &penalty.Amount)
	if err != nil {
		ctx.Logger().Error("failed to slash validator entity",
			"err", err,
			"node_id", node.ID,
			"entity_id", node.EntityID,
		)
		return err
	}

	if err = regState.SetNodeStatus(ctx, node.ID, nodeStatus); err != nil {
		ctx.Logger().Error("failed to set validator node status",
			"err", err,
			"node_id", node.ID,
			"entity_id", node.EntityID,
		)
		return err
	}

	ctx.Logger().Warn("slashed validator",
		"reason", reason,
		"node_id", node.ID,
		"entity_id", node.EntityID,
	)

	return nil
}
