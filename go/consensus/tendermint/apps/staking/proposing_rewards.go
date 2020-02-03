package staking

import (
	"encoding/hex"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

func (app *stakingApplication) resolveEntityIDFromProposer(regState *registryState.MutableState, request types.RequestBeginBlock, ctx *abci.Context) *signature.PublicKey {
	var proposingEntity *signature.PublicKey
	proposerNode, err := regState.NodeByConsensusAddress(request.Header.ProposerAddress)
	if err != nil {
		ctx.Logger().Warn("failed to get proposer node",
			"err", err,
			"address", hex.EncodeToString(request.Header.ProposerAddress),
		)
	} else {
		proposingEntity = &proposerNode.EntityID
	}
	return proposingEntity
}

func (app *stakingApplication) rewardBlockProposing(ctx *abci.Context, stakeState *stakingState.MutableState, proposingEntity *signature.PublicKey) error {
	if proposingEntity == nil {
		return nil
	}

	params, err := stakeState.ConsensusParameters()
	if err != nil {
		return fmt.Errorf("staking mutable state getting consensus parameters: %w", err)
	}

	epoch, err := app.state.GetCurrentEpoch(ctx.Ctx())
	if err != nil {
		return fmt.Errorf("app state getting current epoch: %w", err)
	}
	if epoch == epochtime.EpochInvalid {
		ctx.Logger().Info("rewardBlockProposing: this block does not belong to an epoch. no block proposing reward")
		return nil
	}
	if err = stakeState.AddRewards(epoch, &params.RewardFactorBlockProposed, []signature.PublicKey{*proposingEntity}); err != nil {
		return fmt.Errorf("adding rewards: %w", err)
	}
	return nil
}
