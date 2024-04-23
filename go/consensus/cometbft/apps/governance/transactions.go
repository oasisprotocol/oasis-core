package governance

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func (app *governanceApplication) submitProposal(
	ctx *api.Context,
	state *governanceState.MutableState,
	proposalContent *governance.ProposalContent,
) (*governance.Proposal, error) {
	ctx.Logger().Debug("governance: submit proposal tx",
		"proposal_content", proposalContent,
	)

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	// Validate proposal content basics.
	if err = proposalContent.ValidateBasic(params); err != nil {
		ctx.Logger().Debug("governance: malformed proposal content",
			"content", proposalContent,
			"err", err,
		)
		return nil, governance.ErrInvalidArgument
	}

	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// To not violate the consensus, change parameters proposals should be ignored when disabled.
	if proposalContent.ChangeParameters != nil && !params.EnableChangeParametersProposal {
		return nil, governance.ErrInvalidArgument
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, governance.GasOpSubmitProposal, params.GasCosts); err != nil {
		return nil, err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil, nil
	}

	// Load submitter account.
	submitterAddr := ctx.CallerAddress()
	if !submitterAddr.IsValid() {
		return nil, stakingAPI.ErrForbidden
	}
	stakingState := stakingState.NewMutableState(ctx.State())
	submitter, err := stakingState.Account(ctx, submitterAddr)
	if err != nil {
		return nil, fmt.Errorf("governance: failed to fetch account: %w", err)
	}

	// Check if submitter has enough balance for proposal deposit.
	if submitter.General.Balance.Cmp(&params.MinProposalDeposit) < 0 {
		ctx.Logger().Debug("governance: not enough balance to submit proposal",
			"submitter", submitterAddr,
			"min_proposal_deposit", params.MinProposalDeposit,
		)
		return nil, stakingAPI.ErrInsufficientBalance
	}

	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		ctx.Logger().Error("governance: failed to get epoch",
			"err", err,
		)
		return nil, err
	}

	switch {
	case proposalContent.Upgrade != nil:
		upgrade := proposalContent.Upgrade
		// Ensure upgrade descriptor epoch is far enough in future.
		if upgrade.Descriptor.Epoch < params.UpgradeMinEpochDiff+epoch {
			ctx.Logger().Debug("governance: upgrade descriptor epoch too soon",
				"submitter", submitterAddr,
				"descriptor", upgrade.Descriptor,
				"upgrade_min_epoch_diff", params.UpgradeMinEpochDiff,
				"current_epoch", epoch,
			)
			return nil, governance.ErrUpgradeTooSoon
		}

		// Upgrade is only allowed at the upgrade epoch if there is no pending
		// upgrade UpgradeMinEpochDiff before or after.
		var upgrades []*upgradeAPI.Descriptor
		upgrades, err = state.PendingUpgrades(ctx)
		if err != nil {
			return nil, fmt.Errorf("governance: failed to fetch pending upgrades :%w", err)
		}
		for _, pu := range upgrades {
			if pu.Epoch.AbsDiff(upgrade.Descriptor.Epoch) < params.UpgradeMinEpochDiff {
				return nil, fmt.Errorf("upgrade already scheduled at epoch: %v: %w", pu.Epoch, governance.ErrUpgradeAlreadyPending)
			}
		}

	case proposalContent.CancelUpgrade != nil:
		cancelUpgrade := proposalContent.CancelUpgrade
		// Check if the cancellation upgrade exists.
		var upgrade *governance.UpgradeProposal
		upgrade, err = state.PendingUpgradeProposal(ctx, cancelUpgrade.ProposalID)
		switch err {
		case nil:
		case governance.ErrNoSuchUpgrade:
			ctx.Logger().Debug("governance: cancel upgrade for a non existing pending upgrade",
				"proposal_id", cancelUpgrade.ProposalID,
				"err", err,
			)
			return nil, err
		default:
			ctx.Logger().Error("governance: error loading proposal",
				"proposal_id", cancelUpgrade.ProposalID,
				"err", err,
			)
			return nil, err
		}

		// Ensure upgrade descriptor is far enough in future so that cancellation is still allowed.
		if upgrade.Descriptor.Epoch < params.UpgradeCancelMinEpochDiff+epoch {
			return nil, governance.ErrUpgradeTooSoon
		}

	case proposalContent.ChangeParameters != nil:
		// Notify other interested applications to validate the parameter changes.
		var res interface{}
		res, err = app.md.Publish(ctx, governanceApi.MessageValidateParameterChanges, proposalContent.ChangeParameters)
		if err != nil {
			ctx.Logger().Debug("governance: failed to dispatch validate parameter changes message",
				"err", err,
			)
			return nil, err
		}
		// Exactly one module should be interested in the proposed changes. If no one is,
		// the proposal is rejected as not being supported.
		if res == nil {
			ctx.Logger().Debug("governance: no module interested in change parameters proposal")
			return nil, governance.ErrInvalidArgument
		}
	default:
		return nil, governance.ErrInvalidArgument
	}

	// Deposit proposal funds.
	if err = stakingState.TransferToGovernanceDeposits(
		ctx,
		submitterAddr,
		&params.MinProposalDeposit,
	); err != nil {
		ctx.Logger().Error("governance: failed to deposit governance",
			"err", err,
			"submitter", submitterAddr,
			"deposit", &params.MinProposalDeposit,
		)
		return nil, fmt.Errorf("governance: failed to deposit governance: %w", err)
	}

	// Load the next proposal identifier.
	id, err := state.NextProposalIdentifier(ctx)
	if err != nil {
		ctx.Logger().Error("governance: failed to get next proposal identifier",
			"err", err,
		)
		return nil, fmt.Errorf("governance: failed to get next proposal identifier: %w", err)
	}
	if err := state.SetNextProposalIdentifier(ctx, id+1); err != nil {
		ctx.Logger().Error("governance: failed to set next proposal identifier",
			"err", err,
		)
		return nil, fmt.Errorf("governance: failed to set next proposal identifier: %w", err)
	}
	// Create the proposal.
	proposal := &governance.Proposal{
		ID:        id,
		ClosesAt:  epoch + params.VotingPeriod,
		Content:   *proposalContent,
		CreatedAt: epoch,
		Deposit:   params.MinProposalDeposit,
		State:     governance.StateActive,
		Submitter: submitterAddr,
	}
	if err := state.SetActiveProposal(ctx, proposal); err != nil {
		ctx.Logger().Error("governance: failed to set active proposal",
			"err", err,
		)
		return nil, fmt.Errorf("governance: failed to set active proposal: %w", err)
	}

	// Emit events.
	// Proposal submitted.
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&governance.ProposalSubmittedEvent{
		ID:        proposal.ID,
		Submitter: proposal.Submitter,
	}))

	return proposal, nil
}

func (app *governanceApplication) castVote(
	ctx *api.Context,
	state *governanceState.MutableState,
	proposalVote *governance.ProposalVote,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("governance: failed to fetch consensus parameters: %w", err)
	}

	// Charge gas for this transaction.
	if err = ctx.Gas().UseGas(1, governance.GasOpCastVote, params.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	submitterAddr := ctx.CallerAddress()
	if !submitterAddr.IsValid() {
		return stakingAPI.ErrForbidden
	}

	// Query signer entity descriptor.
	var submitterNodes []signature.PublicKey
	registryState := registryState.NewMutableState(ctx.State())
	submitterEntity, err := registryState.Entity(ctx, ctx.TxSigner())
	switch err {
	case nil:
		submitterNodes = submitterEntity.Nodes
	case registryAPI.ErrNoSuchEntity:
		if !params.AllowVoteWithoutEntity {
			return governance.ErrNotEligible
		}
		// Default to an empty set of nodes so delegators without entities can vote.
	default:
		return fmt.Errorf("governance: failed to query entity: %w", err)
	}

	// Load current validator sets.
	schedulerState := schedulerState.NewMutableState(ctx.State())
	currentValidators, err := schedulerState.CurrentValidators(ctx)
	if err != nil {
		return fmt.Errorf("governance: failed to query current validators: %w", err)
	}
	currentValidatorsByNodeID := make(map[signature.PublicKey]*schedulerAPI.Validator, len(currentValidators))
	for _, v := range currentValidators {
		currentValidatorsByNodeID[v.ID] = v
	}

	// Submitter is eligible if any of its nodes are a current validator.
	var eligible bool
	for _, nID := range submitterNodes {
		if _, ok := currentValidatorsByNodeID[nID]; ok {
			eligible = true
			break
		}
	}
	// Or if the submitter is a delegator to a current validator.
	if !eligible {
		// Validators map by entity address.
		currentValidatorsByEntityAddress := make(map[stakingAPI.Address]*schedulerAPI.Validator, len(currentValidators))
		for _, v := range currentValidators {
			currentValidatorsByEntityAddress[stakingAPI.NewAddress(v.EntityID)] = v
		}
		// Query delegations.
		stakingState := stakingState.NewMutableState(ctx.State())
		var delegs map[stakingAPI.Address]*stakingAPI.Delegation
		delegs, err = stakingState.DelegationsFor(ctx, submitterAddr)
		if err != nil {
			return fmt.Errorf("governance: failed to query submitter delegations: %w", err)
		}
		// Check if submitter delegates to any validator entity.
		for d := range delegs {
			if _, ok := currentValidatorsByEntityAddress[d]; ok {
				eligible = true
				break
			}
		}
	}

	if !eligible {
		ctx.Logger().Debug("governance: submitter not eligible to vote",
			"submitter", ctx.CallerAddress(),
		)
		return governance.ErrNotEligible
	}

	// Load proposal.
	proposal, err := state.Proposal(ctx, proposalVote.ID)
	switch err {
	case nil:
	case governance.ErrNoSuchProposal:
		ctx.Logger().Debug("governance: vote for a missing proposal",
			"proposal_id", proposalVote.ID,
		)
		return governance.ErrNoSuchProposal
	default:
		ctx.Logger().Debug("governance: error loading proposal",
			"err", err,
			"proposal_id", proposalVote.ID,
		)
	}
	// Ensure proposal is active.
	if proposal.State != governance.StateActive {
		ctx.Logger().Error("governance: vote for a non-active proposal",
			"proposal_id", proposalVote.ID,
			"state", proposal.State,
			"proposal", proposal,
			"vote", proposalVote,
		)
		return governance.ErrVotingIsClosed
	}

	// Save the vote.
	if err := state.SetVote(ctx, proposal.ID, submitterAddr, proposalVote.Vote); err != nil {
		return fmt.Errorf("governance: failed to save the vote: %w", err)
	}

	// Emit event.
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&governance.VoteEvent{
		ID:        proposal.ID,
		Submitter: submitterAddr,
		Vote:      proposalVote.Vote,
	}))

	return nil
}
