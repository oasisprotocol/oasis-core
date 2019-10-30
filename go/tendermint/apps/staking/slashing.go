package staking

import (
	"context"
	"encoding/hex"
	"time"

	tmcrypto "github.com/tendermint/tendermint/crypto"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
)

func (app *stakingApplication) onEvidenceDoubleSign(
	ctx *abci.Context,
	addr tmcrypto.Address,
	height int64,
	time time.Time,
	power int64,
) error {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	// Resolve consensus node. Note that in order for this to work even in light
	// of node expirations, the node descriptor must be available for at least
	// the debonding period after expiration.
	node, err := regState.NodeByConsensusAddress(addr)
	if err != nil {
		app.logger.Warn("failed to get validator node",
			"err", err,
			"address", hex.EncodeToString(addr),
		)
		return nil
	}

	nodeStatus, err := regState.NodeStatus(node.ID)
	if err != nil {
		app.logger.Warn("failed to get validator node status",
			"err", err,
			"node_id", node.ID,
		)
		return nil
	}

	// Do not slash a frozen validator.
	if nodeStatus.IsFrozen() {
		app.logger.Debug("not slashing frozen validator",
			"node_id", node.ID,
			"entity_id", node.EntityID,
			"freeze_end_time", nodeStatus.FreezeEndTime,
		)
		return nil
	}

	// Retrieve the slash procedure for double signing.
	st, err := stakeState.Slashing()
	if err != nil {
		app.logger.Error("failed to get slashing table entry for double signing",
			"err", err,
		)
		return err
	}

	penalty := st[staking.SlashDoubleSigning]

	// Freeze validator to prevent it being slashed again. This also prevents the
	// validator from being scheduled in the next epoch.
	if penalty.FreezeInterval > 0 {
		var epoch epochtime.EpochTime
		epoch, err = app.timeSource.GetEpoch(context.Background(), ctx.BlockHeight()+1)
		if err != nil {
			return err
		}

		nodeStatus.FreezeEndTime = epoch + penalty.FreezeInterval
	}

	// Slash validator.
	_, err = stakeState.SlashEscrow(ctx, node.EntityID, &penalty.Share)
	if err != nil {
		app.logger.Error("failed to slash validator entity",
			"err", err,
			"node_id", node.ID,
			"entity_id", node.EntityID,
		)
		return err
	}

	if err = regState.SetNodeStatus(node.ID, nodeStatus); err != nil {
		app.logger.Error("failed to set validator node status",
			"err", err,
			"node_id", node.ID,
			"entity_id", node.EntityID,
		)
		return err
	}

	app.logger.Warn("slashed validator for double signing",
		"node_id", node.ID,
		"entity_id", node.EntityID,
	)

	return nil
}
