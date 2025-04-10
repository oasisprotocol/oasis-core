package governance

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	registryapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/api"
	schedulerapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

type Application struct {
	state api.ApplicationState
	md    api.MessageDispatcher
}

func (app *Application) Name() string {
	return AppName
}

func (app *Application) ID() uint8 {
	return AppID
}

func (app *Application) Methods() []transaction.MethodName {
	return governance.Methods
}

func (app *Application) Blessed() bool {
	return false
}

func (app *Application) Dependencies() []string {
	return []string{registryapp.AppName, schedulerapp.AppName, stakingapp.AppName}
}

func (app *Application) OnRegister(md api.MessageDispatcher) {
	app.md = md

	// Subscribe to messages emitted by other apps.
	md.Subscribe(roothashApi.RuntimeMessageGovernance, app)
	md.Subscribe(api.MessageStateSyncCompleted, app)
	md.Subscribe(governanceApi.MessageChangeParameters, app)
	md.Subscribe(governanceApi.MessageValidateParameterChanges, app)
}

func (app *Application) OnCleanup() {
}

func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	state := governanceState.NewMutableState(ctx.State())

	ctx.Logger().Debug("executing governance tx",
		"tx", tx,
	)

	ctx.SetPriority(AppPriority)

	switch tx.Method {
	case governance.MethodSubmitProposal:
		var proposalContent governance.ProposalContent
		if err := cbor.Unmarshal(tx.Body, &proposalContent); err != nil {
			ctx.Logger().Debug("governance: failed to unmarshal proposal content",
				"err", err,
			)
			return governance.ErrInvalidArgument
		}
		_, err := app.submitProposal(ctx, state, &proposalContent)
		return err
	case governance.MethodCastVote:
		var proposalVote governance.ProposalVote
		if err := cbor.Unmarshal(tx.Body, &proposalVote); err != nil {
			ctx.Logger().Debug("governance: failed to unmarshal proposal vote",
				"err", err,
			)
			return governance.ErrInvalidArgument
		}
		return app.castVote(ctx, state, &proposalVote)
	default:
		return governance.ErrInvalidArgument
	}
}

func (app *Application) ExecuteMessage(ctx *api.Context, kind, msg any) (any, error) {
	switch kind {
	case roothashApi.RuntimeMessageGovernance:
		m := msg.(*message.GovernanceMessage)
		switch {
		case m.CastVote != nil:
			state := governanceState.NewMutableState(ctx.State())
			return nil, app.castVote(ctx, state, m.CastVote)
		case m.SubmitProposal != nil:
			state := governanceState.NewMutableState(ctx.State())
			return app.submitProposal(ctx, state, m.SubmitProposal)
		default:
			return nil, governance.ErrInvalidArgument
		}
	case api.MessageStateSyncCompleted:
		return app.completeStateSync(ctx)
	case governanceApi.MessageValidateParameterChanges:
		// A change parameters proposal is about to be submitted. Validate changes.
		return app.changeParameters(ctx, msg, false)
	case governanceApi.MessageChangeParameters:
		// A change parameters proposal has just been accepted and closed. Validate and apply
		// changes.
		return app.changeParameters(ctx, msg, true)
	default:
		return nil, governance.ErrInvalidArgument
	}
}

func (app *Application) BeginBlock(ctx *api.Context) error {
	// Check if epoch has changed.
	epochChanged, epoch := app.state.EpochChanged(ctx)
	if !epochChanged {
		// Nothing to do.
		return nil
	}

	// Check if a pending upgrade is scheduled for current epoch.
	state := governanceState.NewMutableState(ctx.State())
	pendingUpgrades, err := state.PendingUpgrades(ctx)
	if err != nil {
		return fmt.Errorf("cometbft/governance: couldn't get pending upgrades: %w", err)
	}
	var ud *upgrade.Descriptor
	for _, pendingUpgrade := range pendingUpgrades {
		if pendingUpgrade.Epoch == epoch {
			ud = pendingUpgrade
			break
		}
	}
	if ud == nil {
		ctx.Logger().Debug("no pending upgrades scheduled for current epoch",
			"epoch", epoch,
			"pending_upgrades", pendingUpgrades,
		)
		// No upgrade scheduled for current epoch.
		return nil
	}

	ctx.Logger().Info("pending upgrade scheduled for this epoch",
		"epoch", epoch,
		"upgrade", ud,
	)

	// Check if the upgrade descriptor is installed in the node and has been executed.
	if upgrader := ctx.AppState().Upgrader(); upgrader != nil {
		switch pu, err := upgrader.GetUpgrade(ud); err {
		case nil:
			// Upgrade exists, make sure it is in the process of being applied.
			if !pu.HasStage(upgrade.UpgradeStageStartup) {
				ctx.Logger().Error("upgrade pending but not being applied",
					"handler", ud.Handler,
					"epoch", ud.Epoch,
					"upgrade_height", pu.UpgradeHeight,
					"last_completed_stage", pu.LastCompletedStage,
				)
				return upgrade.ErrStopForUpgrade
			}
		case upgrade.ErrUpgradeNotFound:
			// The upgrade does not exist.
			ctx.Logger().Error("upgrade handler does not exist",
				"handler", ud.Handler,
				"epoch", ud.Epoch,
				"upgrade_height", pu.UpgradeHeight,
				"last_completed_stage", pu.LastCompletedStage,
			)
			return upgrade.ErrStopForUpgrade
		default:
			// Unknown error.
			ctx.Logger().Error("failed to verify pending upgrade status",
				"err", err,
			)
			return upgrade.ErrStopForUpgrade
		}
	}

	ctx.Logger().Info("running version compatible, removing pending upgrade",
		"epoch", epoch,
	)
	// If we are running the correct version, remove the pending upgrade - the upgrader should have
	// handeled the upgrade already.
	if err := state.RemovePendingUpgradesForEpoch(ctx, epoch); err != nil {
		return fmt.Errorf("cometbft/governance: couldn't remove pending upgrades for epoch: %w", err)
	}

	return nil
}

// executeProposal executed the proposal.
//
// The method modifies the passed proposal.
func (app *Application) executeProposal(ctx *api.Context, state *governanceState.MutableState, proposal *governance.Proposal) error {
	// If proposal execution fails, the proposal's state is changed to StateFailed.
	proposal.State = governance.StateFailed

	switch {
	case proposal.Content.Upgrade != nil:
		params, err := state.ConsensusParameters(ctx)
		if err != nil {
			return fmt.Errorf("failed to query consensus parameters: %w", err)
		}

		// Upgrade is only allowed at the upgrade epoch if there is no pending
		// upgrade UpgradeMinEpochDiff before or after.
		upgrades, err := state.PendingUpgrades(ctx)
		if err != nil {
			return fmt.Errorf("failed to query upgrades: %w", err)
		}
		for _, pu := range upgrades {
			if pu.Epoch.AbsDiff(proposal.Content.Upgrade.Descriptor.Epoch) < params.UpgradeMinEpochDiff {
				return fmt.Errorf("upgrade already scheduled at epoch: %v: %w", pu.Epoch, governance.ErrUpgradeAlreadyPending)
			}
		}

		// Execute upgrade proposal.
		err = state.SetPendingUpgrade(ctx, proposal.ID, &proposal.Content.Upgrade.Descriptor)
		if err != nil {
			return fmt.Errorf("failed to set pending upgrade: %w", err)
		}

		// Locally apply the upgrade proposal.
		if upgrader := ctx.AppState().Upgrader(); upgrader != nil {
			if err = upgrader.SubmitDescriptor(&proposal.Content.Upgrade.Descriptor); err != nil {
				ctx.Logger().Error("failed to locally apply the upgrade descriptor",
					"err", err,
					"descriptor", proposal.Content.Upgrade.Descriptor,
				)
			}
		}
	case proposal.Content.CancelUpgrade != nil:
		cancelingProposal, err := state.Proposal(ctx, proposal.Content.CancelUpgrade.ProposalID)
		if err != nil {
			return fmt.Errorf("failed to query proposal: %w", err)
		}
		if cancelingProposal.Content.Upgrade == nil {
			return fmt.Errorf("%w: canceling proposal needs to be an upgrade proposal", governance.ErrNoSuchUpgrade)
		}
		upgradeProposal, err := state.PendingUpgradeProposal(ctx, cancelingProposal.ID)
		if err != nil {
			return fmt.Errorf("failed to get pending upgrade: %w", err)
		}
		err = state.RemovePendingUpgrade(ctx, cancelingProposal.Content.Upgrade.Epoch, cancelingProposal.ID)
		if err != nil {
			return fmt.Errorf("failed to remove pending upgrade: %w", err)
		}

		// Locally cancel the upgrade proposal.
		if upgrader := ctx.AppState().Upgrader(); upgrader != nil {
			if err = upgrader.CancelUpgrade(&upgradeProposal.Descriptor); err != nil {
				ctx.Logger().Error("failed to locally cancel the upgrade",
					"err", err,
					"descriptor", upgradeProposal.Descriptor,
				)
			}
		}
	case proposal.Content.ChangeParameters != nil:
		// To not violate the consensus, change parameters proposals should be ignored when
		// disabled.
		params, err := state.ConsensusParameters(ctx)
		if err != nil {
			ctx.Logger().Error("failed to query consensus parameters",
				"err", err,
			)
			return governance.ErrInvalidArgument
		}
		if !params.EnableChangeParametersProposal {
			ctx.Logger().Debug("change parameters proposals are disabled")
			return governance.ErrInvalidArgument
		}

		// Notify other interested applications about the change parameters proposal.
		res, err := app.md.Publish(ctx, governanceApi.MessageChangeParameters, proposal.Content.ChangeParameters)
		if err != nil {
			ctx.Logger().Debug("failed to dispatch change parameters proposal message",
				"err", err,
			)
			return err
		}

		// Exactly one module should apply the proposed changes. If no one does, the proposal
		// is rejected as not being supported.
		if res == nil {
			ctx.Logger().Debug("governance: no module applied change parameters proposal")
			return governance.ErrInvalidArgument
		}
	default:
		return governance.ErrInvalidArgument
	}

	proposal.State = governance.StatePassed
	// If successful, emit Proposal executed event.
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&governance.ProposalExecutedEvent{
		ID: proposal.ID,
	}))

	return nil
}

func validatorsEscrow(
	ctx context.Context,
	stakingState *stakingState.ImmutableState,
	schedulerState *schedulerState.ImmutableState,
) (*quantity.Quantity, map[stakingAPI.Address]*stakingAPI.SharePool, error) {
	currentValidators, err := schedulerState.CurrentValidators(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query current validators: %w", err)
	}

	totalVotingStake := quantity.NewQuantity()
	validatorEntitiesEscrow := make(map[stakingAPI.Address]*stakingAPI.SharePool)

	for _, validator := range currentValidators {
		entityAddr := stakingAPI.NewAddress(validator.EntityID)

		// If there are multiple nodes in the validator set belonging to the same entity,
		// only count the entity escrow once.
		if validatorEntitiesEscrow[entityAddr] != nil {
			continue
		}

		var account *stakingAPI.Account
		account, err = stakingState.Account(ctx, entityAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query validator account: %w", err)
		}

		validatorEntitiesEscrow[entityAddr] = &account.Escrow.Active
		if err := totalVotingStake.Add(&account.Escrow.Active.Balance); err != nil {
			return nil, nil, fmt.Errorf("failed to add to totalVotingStake: %w", err)
		}
	}
	return totalVotingStake, validatorEntitiesEscrow, nil
}

// closeProposal closes an active proposal.
//
// This method modifies the passed proposal.
func (app *Application) closeProposal(
	ctx *api.Context,
	state *governanceState.MutableState,
	stakingState *stakingState.ImmutableState,
	totalVotingStake quantity.Quantity,
	validatorEntitiesPool map[stakingAPI.Address]*stakingAPI.SharePool,
	proposal *governance.Proposal,
) error {
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	votes, err := state.Votes(ctx, proposal.ID)
	if err != nil {
		return fmt.Errorf("failed to query votes: %w", err)
	}

	ctx.Logger().Debug("tallying votes",
		"proposal", proposal,
		"total_voting_stake", totalVotingStake,
		"validator_entities_pool", validatorEntitiesPool,
		"votes", votes,
	)
	validatorVotes := make(map[stakingAPI.Address]*governance.Vote)
	validatorVoteShares := make(map[stakingAPI.Address]map[governance.Vote]quantity.Quantity)
	for validator := range validatorEntitiesPool {
		validatorVoteShares[validator] = make(map[governance.Vote]quantity.Quantity)
	}

	// Tally the validator votes.
	for _, vote := range votes {
		escrow, ok := validatorEntitiesPool[vote.Voter]
		if !ok {
			// Skip non-validator votes.
			continue
		}
		validatorVotes[vote.Voter] = &vote.Vote //nolint:gosec
		if err = addShares(validatorVoteShares[vote.Voter], vote.Vote, escrow.TotalShares); err != nil {
			return fmt.Errorf("failed to add shares: %w", err)
		}
	}

	// Tally delegator votes.
	for _, vote := range votes {
		// Fetch outgoing delegations.
		delegations, err := stakingState.DelegationsFor(ctx, vote.Voter)
		if err != nil {
			ctx.Logger().Error("failed to fetch delegations for",
				"delegator", vote.Voter,
				"err", err,
			)
			return fmt.Errorf("failed to fetch delegations: %w", err)
		}
		var delegationToValidator bool
		for to, delegation := range delegations {
			if _, ok := validatorEntitiesPool[to]; !ok {
				continue
			}
			delegationToValidator = true
			validatorVote := validatorVotes[to]

			// Skip if vote matches the delegated validator vote.
			if validatorVote != nil && *validatorVote == vote.Vote {
				continue
			}

			// Deduct shares from the validators shares.
			if validatorVote != nil {
				if err := subShares(validatorVoteShares[to], *validatorVote, delegation.Shares); err != nil {
					return fmt.Errorf("failed to sub votes: %w", err)
				}
			}

			// Add shares to the voters vote.
			if err := addShares(validatorVoteShares[to], vote.Vote, delegation.Shares); err != nil {
				return fmt.Errorf("failed to add votes: %w", err)
			}
		}
		if !delegationToValidator {
			proposal.InvalidVotes++
		}
	}

	// Finalize the voting results - convert votes in shares into results in stake.
	proposal.Results = make(map[governance.Vote]quantity.Quantity)
	for validator, votes := range validatorVoteShares {
		validatorPool, ok := validatorEntitiesPool[validator]
		if !ok {
			// This should NEVER happen.
			panic("governance: missing validator pool")
		}
		for vote, shares := range votes {
			// Compute stake from shares.
			escrow, err := validatorPool.StakeForShares(shares.Clone())
			if err != nil {
				ctx.Logger().Error("failed to compute stake from shares for",
					"share_pool", validatorPool,
					"validator", validator,
					"err", err,
				)
				return fmt.Errorf("failed to compute stake from shares: %w", err)

			}

			// Add stake to vote.
			currentVotes := proposal.Results[vote]
			if err := currentVotes.Add(escrow); err != nil {
				return fmt.Errorf("failed to add votes: %w", err)
			}
			proposal.Results[vote] = currentVotes
		}
	}

	ctx.Logger().Debug("close proposal",
		"total_voting_state", totalVotingStake,
		"results", proposal.Results,
		"invalid_votes", proposal.InvalidVotes,
		"stake_threshold", params.StakeThreshold,
	)
	return proposal.CloseProposal(totalVotingStake, params.StakeThreshold)
}

func addShares(validatorVoteShares map[governance.Vote]quantity.Quantity, vote governance.Vote, amount quantity.Quantity) error {
	amt := amount.Clone()
	currShares := validatorVoteShares[vote]
	if err := amt.Add(&currShares); err != nil {
		return fmt.Errorf("failed to add votes: %w", err)
	}
	validatorVoteShares[vote] = *amt
	return nil
}

func subShares(validatorVoteShares map[governance.Vote]quantity.Quantity, vote governance.Vote, amount quantity.Quantity) error {
	amt := amount.Clone()
	currShares := validatorVoteShares[vote]
	if err := currShares.Sub(amt); err != nil {
		return fmt.Errorf("failed to sub votes: %w", err)
	}
	validatorVoteShares[vote] = currShares
	return nil
}

func (app *Application) EndBlock(ctx *api.Context) (types.ResponseEndBlock, error) {
	// Check if epoch has changed.
	epochChanged, epoch := app.state.EpochChanged(ctx)
	if !epochChanged {
		// Nothing to do.
		return types.ResponseEndBlock{}, nil
	}

	state := governanceState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}

	activeProposals, err := state.ActiveProposals(ctx)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("cometbft/governance: couldn't get active proposals: %w", err)
	}
	// Get proposals that are closed this epoch.
	var closingProposals []*governance.Proposal
	for _, proposal := range activeProposals {
		if proposal.ClosesAt != epoch {
			continue
		}
		closingProposals = append(closingProposals, proposal)
	}

	// No proposals closing this epoch.
	if len(closingProposals) == 0 {
		ctx.Logger().Debug("no proposals scheduled to be closed this epoch")
		return types.ResponseEndBlock{}, nil
	}

	ctx.Logger().Debug("proposals scheduled to be closed this epoch",
		"n_proposals", len(closingProposals),
	)

	// Prepare validator set entities state.
	stakingState := stakingState.NewMutableState(ctx.State())
	totalVotingStake, validatorEntitiesEscrow, err := validatorsEscrow(
		ctx,
		stakingState.ImmutableState,
		schedulerState.NewMutableState(ctx.State()).ImmutableState,
	)
	if err != nil {
		return types.ResponseEndBlock{}, fmt.Errorf("consensus/governance: failed to compute validators escrow: %w", err)
	}

	if totalVotingStake.IsZero() {
		return types.ResponseEndBlock{}, fmt.Errorf("consensus/governance: total voting stake is zero")
	}

	for _, proposal := range closingProposals {
		ctx.Logger().Debug("closing proposal",
			"proposal", proposal,
		)
		if err = app.closeProposal(
			ctx,
			state,
			stakingState.ImmutableState,
			*totalVotingStake,
			validatorEntitiesEscrow,
			proposal,
		); err != nil {
			ctx.Logger().Error("proposal closing failure",
				"err", err,
				"proposal", proposal,
				"params", params,
				"total_voting_stake", totalVotingStake,
				"len_validator_entities_escrow", len(validatorEntitiesEscrow),
			)
			return types.ResponseEndBlock{}, fmt.Errorf("consensus/governance: failed to close a proposal: %w", err)
		}

		ctx.Logger().Debug("proposal closed",
			"proposal", proposal,
			"state", proposal.State,
		)

		// In case the proposal is passed, the proposal content is executed.
		if proposal.State == governance.StatePassed {
			// Execute.
			if err = app.executeProposal(ctx, state, proposal); err != nil {
				ctx.Logger().Error("proposal execution failure",
					"err", err,
					"proposal", proposal,
				)
			}
		}

		// Save the updated proposal.
		if err = state.SetProposal(ctx, proposal); err != nil {
			return types.ResponseEndBlock{}, fmt.Errorf("failed to save proposal: %w", err)
		}
		// Remove proposal from active list.
		if err = state.RemoveActiveProposal(ctx, proposal); err != nil {
			return types.ResponseEndBlock{}, fmt.Errorf("failed to remove active proposal: %w", err)
		}

		// Emit Proposal finalized event.
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&governance.ProposalFinalizedEvent{
			ID:    proposal.ID,
			State: proposal.State,
		}))

		switch proposal.State {
		case governance.StatePassed, governance.StateFailed:
			// Transfer back proposal deposits.
			if err = stakingState.TransferFromGovernanceDeposits(
				ctx,
				proposal.Submitter,
				&proposal.Deposit, //nolint:gosec
			); err != nil {
				ctx.Logger().Error("failed to transfer from governance deposits",
					"err", err,
					"submitter", proposal.Submitter,
					"deposit", proposal.Deposit,
				)
				return types.ResponseEndBlock{},
					fmt.Errorf("consensus/governance: failed to reclaim proposal deposit: %w", err)
			}
		case governance.StateRejected:
			// Proposal rejected, deposit is transferred into the common pool.
			if err = stakingState.DiscardGovernanceDeposit(
				ctx,
				&proposal.Deposit, //nolint:gosec
			); err != nil {
				return types.ResponseEndBlock{},
					fmt.Errorf("consensus/governance: failed to discard proposal deposit: %w", err)
			}
		default:
			// Should not ever happen.
			return types.ResponseEndBlock{},
				fmt.Errorf("consensus/governance: invalid closed proposal state: %v", proposal.State)
		}
	}

	return types.ResponseEndBlock{}, nil
}

// New constructs a new governance application instance.
func New(state api.ApplicationState) *Application {
	return &Application{
		state: state,
	}
}
