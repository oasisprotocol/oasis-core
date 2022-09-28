// Package tests is a collection of scheduler implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const recvTimeout = 5 * time.Second

var (
	submitterSigner = stakingTests.Accounts.GetSigner(1)
	submitterAddr   = stakingTests.Accounts.GetAddress(1)
)

// governanceTestsState holds the current state of governance tests.
type governanceTestsState struct {
	proposal *api.Proposal

	submitterBalance *quantity.Quantity

	validatorEntity *entity.Entity
	validatorSigner signature.Signer
	validatorEscrow *quantity.Quantity
	validatorAddr   staking.Address
}

// GovernanceImplementationTests exercises the basic functionality of a
// governance backend.
func GovernanceImplementationTests(
	t *testing.T,
	backend api.Backend,
	consensus consensusAPI.Backend,
	entity *entity.Entity,
	entitySigner signature.Signer,
) {
	require := require.New(t)
	ctx := context.Background()

	state := &governanceTestsState{
		validatorEntity: entity,
		validatorSigner: entitySigner,
		validatorAddr:   staking.NewAddress(entity.ID),
	}

	// Ensure validator has some stake so it can vote on proposals.
	validatorAcc, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{Owner: state.validatorAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")
	state.validatorEscrow = &validatorAcc.Escrow.Active.Balance

	// Submiter is the pre-funded deubg staking account.
	srcAcc, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{Owner: submitterAddr, Height: consensusAPI.HeightLatest})
	require.NoError(err, "Account")
	state.submitterBalance = &srcAcc.General.Balance
	if validatorAcc.Escrow.Active.Balance.IsZero() {
		escrow := &staking.Escrow{
			Account: state.validatorAddr,
			Amount:  *quantity.NewFromUint64(100),
		}
		tx := staking.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
		require.NoError(err, "AddEscrow")
		state.validatorEscrow = quantity.NewFromUint64(100)
		require.NoError(state.submitterBalance.Sub(state.validatorEscrow), "Sub")
	}

	// Query state.
	_, err = backend.StateToGenesis(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "StateToGenesis")

	// Assert empty governance deposits.
	assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, consensusAPI.HeightLatest, quantity.NewQuantity())

	// Run multiple sub-tests. The order of execution is important as bad votes are tested before
	// an upgrade proposal is closed.
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, api.Backend, consensusAPI.Backend, *governanceTestsState)
	}{
		{"TestBadProposals", testBadProposals},
		{"TestUpgradeProposalSubmit", testUpgradeProposalSubmit},
		{"TestBadVotes", testBadVotes},
		{"TestUpgradeProposalVoteAndClose", testUpgradeProposalVoteAndClose},
		{"TestCancelUpgradeProposal", testCancelUpgradeProposal},
		{"TestChangeParametersProposal", testChangeParametersProposal},
	} {
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, backend, consensus, state) })
	}
}

func assertAccountBalance(
	t *testing.T,
	consensus consensusAPI.Backend,
	addr staking.Address,
	height int64,
	expectedBalance *quantity.Quantity,
) {
	require := require.New(t)
	ctx := context.Background()
	acc, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{Owner: addr, Height: height})
	require.NoError(err, "Account")
	require.EqualValues(expectedBalance, &acc.General.Balance, "account should have expected balance")
}

func testBadProposals(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Create an invalid proposal.
	proposal := &api.ProposalContent{}
	tx := api.NewSubmitProposalTx(0, nil, proposal)
	err := consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrInvalidArgument, err, "SubmitProposalTx")

	// Bad cancel proposal.
	proposal = &api.ProposalContent{
		CancelUpgrade: &api.CancelUpgradeProposal{ProposalID: 9999},
	}
	tx = api.NewSubmitProposalTx(0, nil, proposal)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrNoSuchProposal, err, "SubmitProposalTx")

	// Bad change parameters proposal.
	proposal = &api.ProposalContent{
		ChangeParameters: &api.ChangeParametersProposal{},
	}
	tx = api.NewSubmitProposalTx(0, nil, proposal)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrInvalidArgument, err, "SubmitProposalTx")
}

func testBadVotes(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Create an invalid vote.
	vote := &api.ProposalVote{ID: 9999, Vote: api.VoteYes}
	tx := api.NewCastVoteTx(0, nil, vote)
	err := consensusAPI.SignAndSubmitTx(ctx, consensus, testState.validatorSigner, tx)
	require.Equal(api.ErrNoSuchProposal, err, "CastVoteTx")

	// Good vote.
	vote = &api.ProposalVote{ID: testState.proposal.ID, Vote: api.VoteYes}
	tx = api.NewCastVoteTx(0, nil, vote)

	// Submit a good vote with an invalid signer (not a validator).
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrNotEligible, err, "CastVoteTx")
}

func testUpgradeProposalSubmit(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Query current epoch.
	beacon := consensus.Beacon()
	currentEpoch, err := beacon.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// Prepare an upgrade proposal.
	content := &api.ProposalContent{
		Upgrade: &api.UpgradeProposal{
			Descriptor: upgrade.Descriptor{
				Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
				Handler:   "test-upgrade",
				Target:    version.Versions,
				Epoch:     currentEpoch + 200,
			},
		},
	}

	// Submit the proposal but don't close it yet as we would like to test the bad votes also.
	submitProposal(t, content, backend, consensus, testState)
}

func testUpgradeProposalVoteAndClose(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Close the proposal.
	voteAndCloseProposal(t, backend, consensus, testState)

	// Verify that there is one pending upgrade.
	pendingUpgrade, err := backend.PendingUpgrades(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "PendingUpgrades")
	require.Equal(1, len(pendingUpgrade), "There should be one pending upgrade")
}

func testCancelUpgradeProposal(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Prepare a cancel upgrade proposal.
	content := &api.ProposalContent{
		CancelUpgrade: &api.CancelUpgradeProposal{ProposalID: testState.proposal.ID},
	}

	// Submit the proposal.
	submitProposal(t, content, backend, consensus, testState)
	voteAndCloseProposal(t, backend, consensus, testState)

	// Verify that there are no more pending upgrades.
	pendingUpgrade, err := backend.PendingUpgrades(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "PendingUpgrades")
	require.Empty(pendingUpgrade, "no pending upgrades should remain")

	// Test proposals query.
	proposals, err := backend.Proposals(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "Proposals query")
	require.True(len(proposals) > 1, "At least two proposals should exist")
}

func testChangeParametersProposal(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Ensure changes were applied.
	params, err := backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")

	// Prepare a change parameters proposal. Incrementing UpgradeMinEpochDiff parameter should
	// be safe and should not mess with other tests.
	upgradeMinEpochDiff := params.UpgradeMinEpochDiff + 1
	content := &api.ProposalContent{
		ChangeParameters: &api.ChangeParametersProposal{
			Module: api.ModuleName,
			Changes: cbor.Marshal(api.ConsensusParameterChanges{
				UpgradeMinEpochDiff: &upgradeMinEpochDiff,
			}),
		},
	}

	// Submit the proposal.
	submitProposal(t, content, backend, consensus, testState)
	voteAndCloseProposal(t, backend, consensus, testState)

	// Ensure changes were applied.
	params, err = backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")
	require.Equal(upgradeMinEpochDiff, params.UpgradeMinEpochDiff, "UpgradeMinEpochDiff parameter should change")

	// Test proposals query.
	proposals, err := backend.Proposals(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "Proposals query")
	require.True(len(proposals) > 2, "At least three proposals should exist")
}

func submitProposal(t *testing.T, content *api.ProposalContent, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Start watching events before doing any serious work.
	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	// Fetch parameters to get min proposal deposit.
	params, err := backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")

	// Submit the proposal content.
	tx := api.NewSubmitProposalTx(0, nil, content)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.NoError(err, "SubmitProposalTx")

	var ev *api.Event
	var proposal *api.Proposal

WaitForSubmittedProposal:
	for {
		select {
		case ev = <-ch:
			if ev.ProposalSubmitted == nil {
				continue
			}

			proposal, err = backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: ev.ProposalSubmitted.ID})
			require.NoError(err, "Proposal query")

			// Skip if this is not the proposal content we submitted earlier.
			if !proposal.Content.Equals(content) {
				continue
			}

			break WaitForSubmittedProposal
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive proposal submitted event")
		}
	}

	// Validate the proposal.
	require.EqualValues(submitterAddr, proposal.Submitter, "proposal submitter should be correct")

	// Active proposals should return the proposal.
	var activeProposals []*api.Proposal
	activeProposals, err = backend.ActiveProposals(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ActiveProposals")
	require.Len(activeProposals, 1, "one active proposal should be returned")
	require.EqualValues(proposal, activeProposals[0], "expected proposal should be returned")

	// Backend events should contain the event.
	var evs []*api.Event
	evs, err = backend.GetEvents(ctx, ev.Height)
	require.NoError(err, "GetEvents")
	require.Len(evs, 1, "one event should be returned")
	require.EqualValues(ev, evs[0], "queried event should match")

	// Ensure governance deposit was made.
	assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, ev.Height, &params.MinProposalDeposit)
	expected := testState.submitterBalance.Clone()
	require.NoError(expected.Sub(&params.MinProposalDeposit), "Sub")
	assertAccountBalance(t, consensus, submitterAddr, ev.Height, expected)

	// Save for other tests.
	testState.proposal = proposal
}

func voteAndCloseProposal(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Start watching events before doing any serious work.
	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	// Vote for the submitted cancel proposal.
	vote := &api.ProposalVote{ID: testState.proposal.ID, Vote: api.VoteYes}
	tx := api.NewCastVoteTx(0, nil, vote)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testState.validatorSigner, tx)
	require.NoError(err, "CastVoteTx")

	var ev *api.Event

WaitForSubmittedVote:
	for {
		select {
		case ev = <-ch:
			if ev.Vote == nil {
				continue
			}
			if ev.Vote.ID != testState.proposal.ID {
				continue
			}
			break WaitForSubmittedVote
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive vote event")
		}
	}

	// Validate the vote.
	entAddr := staking.NewAddress(testState.validatorEntity.ID)
	require.EqualValues(api.VoteYes, ev.Vote.Vote, "vote should be a VoteYes vote")
	require.EqualValues(entAddr, ev.Vote.Submitter, "vote submitter should be correct")

	// Query vote.
	votes, err := backend.Votes(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: testState.proposal.ID})
	require.NoError(err, "Votes query")
	require.Len(votes, 1, "one vote should be cast")
	require.EqualValues(ev.Vote.Vote, votes[0].Vote, "vote event should be equal to the queried vote")
	require.EqualValues(ev.Vote.Submitter, votes[0].Voter, "vote event should be equal to the queried vote")

	// Transition to the voting close epoch.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	currentEpoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")
	beaconTests.MustAdvanceEpochMulti(t, timeSource, consensus.Registry(), uint64(testState.proposal.ClosesAt.AbsDiff(currentEpoch)))

	var proposal *api.Proposal

WaitForProposalToBeFinalized:
	for {
		select {
		case ev = <-ch:
			if ev.ProposalFinalized == nil {
				continue
			}
			if ev.ProposalFinalized.ID != testState.proposal.ID {
				continue
			}

			require.EqualValues(api.StatePassed, ev.ProposalFinalized.State, "proposal should pass")

			proposal, err = backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: testState.proposal.ID})
			require.NoError(err, "Proposal query")

			break WaitForProposalToBeFinalized
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive event")
		}
	}

	// Validate the proposal.
	require.EqualValues(api.StatePassed, proposal.State, "proposal should pass")
	require.EqualValues(map[api.Vote]quantity.Quantity{
		api.VoteYes: *testState.validatorEscrow,
	}, proposal.Results, "proposal results should match")

	// Assert governance deposit was reclaimed.
	assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, consensusAPI.HeightLatest, quantity.NewQuantity())
	assertAccountBalance(t, consensus, submitterAddr, ev.Height, testState.submitterBalance)

	// Test proposals query.
	proposals, err := backend.Proposals(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "Proposals query")
	require.True(len(proposals) > 0, "At least one proposals should exist")
}
