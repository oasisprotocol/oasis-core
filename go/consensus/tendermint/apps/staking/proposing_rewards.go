package staking

import (
	"encoding/hex"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
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
	if proposingEntity != nil {
		epoch, err := app.state.GetEpoch(ctx.Ctx(), app.state.BlockHeight()+1)
		if err != nil {
			return fmt.Errorf("app state getting epoch: %w", err)
		}
		if err = stakeState.AddRewards(epoch, staking.RewardFactorBlockProposed, []signature.PublicKey{*proposingEntity}); err != nil {
			return fmt.Errorf("adding rewards: %w", err)
		}
	}
	return nil
}
