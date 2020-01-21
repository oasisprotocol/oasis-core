package staking

import (
	"encoding/hex"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
)

func (app *stakingApplication) resolveEntityIDsFromVotes(ctx *abci.Context, lastCommitInfo types.LastCommitInfo) []signature.PublicKey {
	regState := registryState.NewMutableState(ctx.State())

	var entityIDs []signature.PublicKey
	for _, a := range lastCommitInfo.Votes {
		if !a.SignedLastBlock {
			continue
		}
		valAddr := a.Validator.Address

		// Map address to node/entity.
		node, err := regState.NodeByConsensusAddress(valAddr)
		if err != nil {
			ctx.Logger().Warn("failed to get validator node",
				"err", err,
				"address", hex.EncodeToString(valAddr),
			)
			continue
		}

		entityIDs = append(entityIDs, node.EntityID)
	}

	return entityIDs
}
