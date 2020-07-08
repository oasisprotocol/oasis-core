package staking

import (
	"encoding/hex"

	"github.com/tendermint/tendermint/abci/types"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *stakingApplication) resolveEntityAddressesFromVotes(ctx *abciAPI.Context, regState *registryState.MutableState, lastCommitInfo types.LastCommitInfo) []staking.Address {
	var entityAddresses []staking.Address
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

		entityAddresses = append(entityAddresses, node.EntityAddress)
	}

	return entityAddresses
}
