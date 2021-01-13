package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func onEvidenceRuntimeEquivocation(
	ctx *abciAPI.Context,
	pk signature.PublicKey,
	runtimeID common.Namespace,
	penaltyAmount *quantity.Quantity,
) error {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	node, err := regState.Node(ctx, pk)
	if err != nil {
		// Node might not exist anymore (old evidence). Or the submitted evidence
		// could be for a non-existing node (submitting "fake" but valid evidence).
		ctx.Logger().Error("failed to get runtime node by signature public key",
			"public_key", pk,
			"err", err,
		)
		return fmt.Errorf("tendermint/roothash: failed to get node by id %s: %w", pk, roothash.ErrInvalidEvidence)
	}

	// Slash runtime node entity
	entityAddr := staking.NewAddress(node.EntityID)
	totalSlashed, err := stakeState.SlashEscrow(ctx, entityAddr, penaltyAmount)
	if err != nil {
		return fmt.Errorf("tendermint/roothash: error slashing account %s: %w", entityAddr, err)
	}
	if totalSlashed.IsZero() {
		return fmt.Errorf("tendermint/roothash: nothing to slash from account %s", entityAddr)
	}

	// Move slashed amount to the runtime account.
	// TODO: part of slashed amount (configurable) should be transferred to the transaction submitter.
	runtimeAddr := staking.NewRuntimeAddress(runtimeID)
	if _, err := stakeState.TransferFromCommon(ctx, runtimeAddr, totalSlashed); err != nil {
		return fmt.Errorf("tendermint/roothash: failed transferring reward to runtime account %s: %w", runtimeAddr, err)
	}

	return nil
}
