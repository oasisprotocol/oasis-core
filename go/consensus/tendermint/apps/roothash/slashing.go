package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func onRuntimeLivenessFailure(ctx *abciAPI.Context, nodeID signature.PublicKey, penaltyAmount *quantity.Quantity) error {
	if penaltyAmount.IsZero() {
		return nil
	}

	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	node, err := regState.Node(ctx, nodeID)
	if err != nil {
		// Node should not be able to disappear on an epoch boundary.
		return fmt.Errorf("failed to fetch node %s: %w", nodeID, err)
	}

	// Slash runtime node entity.
	entityAddr := staking.NewAddress(node.EntityID)
	_, err = stakeState.SlashEscrow(ctx, entityAddr, penaltyAmount)
	if err != nil {
		return fmt.Errorf("error slashing account %s: %w", entityAddr, err)
	}

	return nil
}

func onEvidenceRuntimeEquivocation(
	ctx *abciAPI.Context,
	pk signature.PublicKey,
	runtime *registry.Runtime,
	penaltyAmount *quantity.Quantity,
) error {
	if penaltyAmount.IsZero() {
		return nil
	}

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

	// Slash runtime node entity.
	entityAddr := staking.NewAddress(node.EntityID)
	totalSlashed, err := stakeState.SlashEscrow(ctx, entityAddr, penaltyAmount)
	if err != nil {
		return fmt.Errorf("tendermint/roothash: error slashing account %s: %w", entityAddr, err)
	}
	// Since evidence can be submitted for past rounds, the node can be out of stake.
	if totalSlashed.IsZero() {
		ctx.Logger().Debug("nothing to slash from entity for runtime equivocation",
			"penalty", penaltyAmount,
			"addr", entityAddr,
		)
		return nil
	}

	// If the caller is a node, distribute slashed funds to the controlling entity instead of the
	// caller directly.
	rewardAddr := ctx.CallerAddress()
	callerNode, err := regState.Node(ctx, ctx.TxSigner())
	switch err {
	case nil:
		// Caller is a node, replace reward address with its controlling entity.
		rewardAddr = staking.NewAddress(callerNode.EntityID)
	case registry.ErrNoSuchNode:
		// Not a node, reward the caller directly.
	default:
		return fmt.Errorf("tendermint/roothash: failed to lookup node: %w", err)
	}

	// Distribute slashed funds to runtime and caller.
	runtimePercentage := uint64(runtime.Staking.RewardSlashEquvocationRuntimePercent)
	return distributeSlashedFunds(ctx, totalSlashed, runtimePercentage, runtime.ID, []staking.Address{rewardAddr})
}

func onRuntimeIncorrectResults(
	ctx *abciAPI.Context,
	discrepancyCausers []signature.PublicKey,
	discrepancyResolvers []signature.PublicKey,
	runtime *registry.Runtime,
	penaltyAmount *quantity.Quantity,
) error {
	if penaltyAmount.IsZero() {
		return nil
	}

	stakeState := stakingState.NewMutableState(ctx.State())

	var totalSlashed quantity.Quantity
	for _, pk := range discrepancyCausers {
		entityAddr := staking.NewAddress(pk)

		// Slash entity.
		slashed, err := stakeState.SlashEscrow(ctx, entityAddr, penaltyAmount)
		if err != nil {
			return fmt.Errorf("tendermint/roothash: error slashing account %s: %w", entityAddr, err)
		}
		if err = totalSlashed.Add(slashed); err != nil {
			return fmt.Errorf("tendermint/roothash: totalSlashed.Add(slashed): %w", err)
		}
		ctx.Logger().Debug("runtime node entity slashed for incorrect results",
			"slashed", slashed,
			"total_slashed", totalSlashed,
			"addr", entityAddr,
		)
	}

	// It can happen that nothing was slashed as nodes could be out of stake.
	// A node can be out of stake as stake claims are only checked on epoch transitions
	// and a node can be slashed multiple times per epoch.
	// This should not fail the round, as otherwise a single node without stake could
	// cause round failures until it is removed from the committee (on the next epoch transition).
	if totalSlashed.IsZero() {
		// Nothing more to do in this case.
		return nil
	}

	// Determine who the backup workers' entities to reward are.
	var rewardEntities []staking.Address
	for _, pk := range discrepancyResolvers {
		rewardEntities = append(rewardEntities, staking.NewAddress(pk))
	}

	// Distribute slashed funds to runtime and backup workers' entities.
	runtimePercentage := uint64(runtime.Staking.RewardSlashBadResultsRuntimePercent)
	return distributeSlashedFunds(ctx, &totalSlashed, runtimePercentage, runtime.ID, rewardEntities)
}

func distributeSlashedFunds(
	ctx *abciAPI.Context,
	totalSlashed *quantity.Quantity,
	runtimePercentage uint64,
	runtimeID common.Namespace,
	otherAddresses []staking.Address,
) error {
	stakeState := stakingState.NewMutableState(ctx.State())

	// Runtime account reward.
	runtimeAccReward := totalSlashed.Clone()
	if err := runtimeAccReward.Mul(quantity.NewFromUint64(runtimePercentage)); err != nil {
		return fmt.Errorf("tendermint/roothash: runtimeAccReward.Mul: %w", err)
	}
	if err := runtimeAccReward.Quo(quantity.NewFromUint64(uint64(100))); err != nil {
		return fmt.Errorf("tendermint/roothash: runtimeAccReward.Quo(100): %w", err)
	}
	runtimeAddr := staking.NewRuntimeAddress(runtimeID)
	if _, err := stakeState.TransferFromCommon(ctx, runtimeAddr, runtimeAccReward, false); err != nil {
		return fmt.Errorf("tendermint/roothash: failed transferring reward to %s: %w", runtimeAddr, err)
	}
	ctx.Logger().Debug("runtime account awarded slashed funds",
		"reward", runtimeAccReward,
		"total_slashed", totalSlashed,
		"runtime_addr", runtimeAddr,
	)

	if len(otherAddresses) == 0 {
		// Nothing more to do.
		ctx.Logger().Debug("no other accounts to reward")
		return nil
	}

	// (totalSlashed - runtimeAccReward) / n_reward_entities
	otherReward := totalSlashed.Clone()
	if err := otherReward.Sub(runtimeAccReward); err != nil {
		return fmt.Errorf("tendermint/roothash: remainingReward.Sub(runtimeAccReward): %w", err)
	}
	if err := otherReward.Quo(quantity.NewFromUint64(uint64(len(otherAddresses)))); err != nil {
		return fmt.Errorf("tendermint/roothash: remainingReward.Quo(len(discrepancyResolvers)): %w", err)
	}

	for _, addr := range otherAddresses {
		if _, err := stakeState.TransferFromCommon(ctx, addr, otherReward, true); err != nil {
			return fmt.Errorf("tendermint/roothash: failed transferring reward to %s: %w", addr, err)
		}
		ctx.Logger().Debug("account awarded slashed funds",
			"reward", otherReward,
			"total_slashed", totalSlashed,
			"address", addr,
		)
	}

	return nil
}
