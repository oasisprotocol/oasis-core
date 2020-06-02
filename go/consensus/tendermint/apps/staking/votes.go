package staking

import (
	"encoding/hex"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
)

func (app *stakingApplication) resolveEntityIDsFromVotes(ctx *abciAPI.Context, regState *registryState.MutableState, lastCommitInfo types.LastCommitInfo) []signature.PublicKey {
	var entityIDs []signature.PublicKey
	for _, a := range lastCommitInfo.Votes {
		if !a.SignedLastBlock {
			continue
		}
		valAddr := a.Validator.Address

		// Map address to node/entity.
		node, err := regState.NodeByConsensusAddress(ctx, valAddr)
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
