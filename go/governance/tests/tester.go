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
	submittedProposalID uint64
	proposalCloseEpoch  beacon.EpochTime

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

	for _, tc := range []struct {
		n  string
		fn func(*testing.T, api.Backend, consensusAPI.Backend, *governanceTestsState)
	}{
		{"Proposals", testProposals},
		{"TestVotes", testVotes},
		{"TestProposalClose", testProposalClose},
		{"TestCancelProposalUpgrade", testCancelProposalUpgrade},
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

func testProposals(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	// Query consensus parameters.
	params, err := backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")

	// Query state.
	_, err = backend.StateToGenesis(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "StateToGenesis")

	// Assert empty governance deposits.
	assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, consensusAPI.HeightLatest, quantity.NewQuantity())

	// Query current epoch.
	beacon := consensus.Beacon()
	currentEpoch, err := beacon.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// Start watching governance events.
	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	// Create an invalid proposal.
	proposal := &api.ProposalContent{}
	tx := api.NewSubmitProposalTx(0, nil, proposal)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrInvalidArgument, err, "SubmitProposalTx")

	// Bad cancel proposal.
	proposal = &api.ProposalContent{
		CancelUpgrade: &api.CancelUpgradeProposal{ProposalID: 9999},
	}
	tx = api.NewSubmitProposalTx(0, nil, proposal)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrNoSuchProposal, err, "SubmitProposalTx")

	// Good proposal.
	proposal = &api.ProposalContent{
		Upgrade: &api.UpgradeProposal{
			Descriptor: upgrade.Descriptor{
				Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
				Handler:   "test-upgrade",
				Target:    version.Versions,
				Epoch:     currentEpoch + 200,
			},
		},
	}
	tx = api.NewSubmitProposalTx(0, nil, proposal)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.NoError(err, "SubmitProposalTx")

	for {
		select {
		case ev := <-ch:
			if ev.ProposalSubmitted == nil {
				continue
			}
			pID := ev.ProposalSubmitted.ID

			var p *api.Proposal
			p, err = backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: pID})
			require.NoError(err, "Proposal query")

			// Skip if this is not the proposal we submitted earlier.
			if p.Content.Upgrade == nil || !p.Content.Upgrade.Descriptor.Equals(&proposal.Upgrade.Descriptor) {
				continue
			}

			require.EqualValues(proposal.Upgrade.Handler, p.Content.Upgrade.Handler, "expected proposal received")
			require.EqualValues(submitterAddr, p.Submitter, "proposal submitter should be correct")

			testState.submittedProposalID = pID
			testState.proposalCloseEpoch = p.ClosesAt

			// Active proposals should return the proposal.
			var activeProposals []*api.Proposal
			activeProposals, err = backend.ActiveProposals(ctx, consensusAPI.HeightLatest)
			require.NoError(err, "ActiveProposals")
			require.Len(activeProposals, 1, "one active proposal should be returned")
			require.EqualValues(p, activeProposals[0], "expected proposal should be returned")

			var evs []*api.Event
			evs, err = backend.GetEvents(ctx, ev.Height)
			require.NoError(err, "GetEvents")
			require.Len(evs, 1, "one event should be returned")
			require.EqualValues(ev, evs[0], "queried event should match")

			// Assert governace deposit was made.
			assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, ev.Height, &params.MinProposalDeposit)
			expected := testState.submitterBalance.Clone()
			require.NoError(expected.Sub(&params.MinProposalDeposit), "Sub")
			assertAccountBalance(t, consensus, submitterAddr, ev.Height, expected)

			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive proposal submitted event")
		}
	}
}

func testVotes(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	entAddr := staking.NewAddress(testState.validatorEntity.ID)

	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	// Create an invalid vote.
	vote := &api.ProposalVote{ID: 9999, Vote: api.VoteYes}
	tx := api.NewCastVoteTx(0, nil, vote)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testState.validatorSigner, tx)
	require.Equal(api.ErrNoSuchProposal, err, "CastVoteTx")

	// Good vote.
	vote = &api.ProposalVote{ID: testState.submittedProposalID, Vote: api.VoteYes}
	tx = api.NewCastVoteTx(0, nil, vote)

	// Submit a good vote with an invalid signer (not a validator).
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.Equal(api.ErrNotEligible, err, "CastVoteTx")

	// Submit the vote with a validator.
	tx = api.NewCastVoteTx(0, nil, vote)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testState.validatorSigner, tx)
	require.NoError(err, "CastVoteTx")

	for {
		select {
		case ev := <-ch:
			if ev.Vote == nil {
				continue
			}
			if ev.Vote.ID != testState.submittedProposalID {
				continue
			}
			vote := ev.Vote
			require.EqualValues(api.VoteYes, vote.Vote, "vote should be a VoteYes vote")
			require.EqualValues(entAddr, vote.Submitter, "vote submitter should be correct")

			// Query vote.
			votes, err := backend.Votes(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: testState.submittedProposalID})
			require.NoError(err, "Votes query")
			require.Len(votes, 1, "one vote should be cast")
			require.EqualValues(vote.Vote, votes[0].Vote, "vote event should be equal to the queried vote")
			require.EqualValues(vote.Submitter, votes[0].Voter, "vote event should be equal to the queried vote")

			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive proposal vote event")
		}
	}
}

func testProposalClose(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	// Transition to the voting close epoch.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	currentEpoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")
	beaconTests.MustAdvanceEpochMulti(t, timeSource, consensus.Registry(), uint64(testState.proposalCloseEpoch.AbsDiff(currentEpoch)))

	for {
		select {
		case ev := <-ch:
			if ev.ProposalFinalized == nil {
				continue
			}
			if ev.ProposalFinalized.ID != testState.submittedProposalID {
				continue
			}
			require.EqualValues(api.StatePassed, ev.ProposalFinalized.State, "proposal should pass")

			proposal, err := backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: testState.submittedProposalID})
			require.NoError(err, "Proposal query")

			require.EqualValues(api.StatePassed, proposal.State, "proposal should pass")
			require.EqualValues(map[api.Vote]quantity.Quantity{
				api.VoteYes: *testState.validatorEscrow,
			}, proposal.Results, "proposal results should match")

			pendingUpgrade, err := backend.PendingUpgrades(ctx, consensusAPI.HeightLatest)
			require.NoError(err, "PendingUpgrades")
			require.Len(pendingUpgrade, 1, "one upgrade should be pending")
			require.EqualValues(&proposal.Content.Upgrade.Descriptor, pendingUpgrade[0], "pending upgrade should match")

			// Assert governance deposit was reclaimed.
			assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, ev.Height, quantity.NewFromUint64(0))
			assertAccountBalance(t, consensus, submitterAddr, ev.Height, testState.submitterBalance)

			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive event")
		}
	}
}

func testCancelProposalUpgrade(t *testing.T, backend api.Backend, consensus consensusAPI.Backend, testState *governanceTestsState) {
	require := require.New(t)
	ctx := context.Background()

	params, err := backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")

	ch, sub, err := backend.WatchEvents(ctx)
	require.NoError(err, "WatchEvents")
	defer sub.Close()

	cancelProposalContent := &api.ProposalContent{
		CancelUpgrade: &api.CancelUpgradeProposal{ProposalID: testState.submittedProposalID},
	}
	tx := api.NewSubmitProposalTx(0, nil, cancelProposalContent)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitterSigner, tx)
	require.NoError(err, "SubmitProposalTx")

	var cancelProposal *api.Proposal

WaitForSubmittedProposal:
	for {
		select {
		case ev := <-ch:
			if ev.ProposalSubmitted == nil {
				continue
			}

			var p *api.Proposal
			p, err = backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: ev.ProposalSubmitted.ID})
			require.NoError(err, "Proposal query")
			// Skip if this is not the cancel proposal we submitted earlier.
			if p.Content.CancelUpgrade == nil || p.Content.CancelUpgrade.ProposalID != testState.submittedProposalID {
				continue
			}

			cancelProposal = p

			// Ensure governance deposit was made.
			assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, ev.Height, &params.MinProposalDeposit)
			expected := testState.submitterBalance.Clone()
			require.NoError(expected.Sub(&params.MinProposalDeposit), "Sub")
			assertAccountBalance(t, consensus, submitterAddr, ev.Height, expected)

			break WaitForSubmittedProposal
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive proposal submitted event")
		}
	}

	// Vote for the submitted cancel proposal.
	vote := &api.ProposalVote{ID: cancelProposal.ID, Vote: api.VoteYes}
	tx = api.NewCastVoteTx(0, nil, vote)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, testState.validatorSigner, tx)
	require.NoError(err, "CastVoteTx")

WaitForSubmittedVote:
	for {
		select {
		case ev := <-ch:
			if ev.Vote == nil {
				continue
			}
			if ev.Vote.ID != cancelProposal.ID {
				continue
			}
			break WaitForSubmittedVote
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive vote event")
		}
	}

	// Transition to the voting close epoch.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	currentEpoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")
	beaconTests.MustAdvanceEpochMulti(t, timeSource, consensus.Registry(), uint64(cancelProposal.ClosesAt.AbsDiff(currentEpoch)))

	// Ensure pending upgrade was removed.
	for {
		select {
		case ev := <-ch:
			if ev.ProposalFinalized == nil {
				continue
			}
			if ev.ProposalFinalized.ID != cancelProposal.ID {
				continue
			}
			require.EqualValues(api.StatePassed, ev.ProposalFinalized.State, "proposal should pass")

			proposal, err := backend.Proposal(ctx, &api.ProposalQuery{Height: consensusAPI.HeightLatest, ProposalID: testState.submittedProposalID})
			require.NoError(err, "Proposal query")

			require.EqualValues(api.StatePassed, proposal.State, "proposal should pass")
			require.EqualValues(map[api.Vote]quantity.Quantity{
				api.VoteYes: *testState.validatorEscrow,
			}, proposal.Results, "proposal results should match")

			pendingUpgrade, err := backend.PendingUpgrades(ctx, consensusAPI.HeightLatest)
			require.NoError(err, "PendingUpgrades")
			require.Empty(pendingUpgrade, "no pending upgrades should remain")

			// Assert governance deposit was reclaimed.
			assertAccountBalance(t, consensus, staking.GovernanceDepositsAddress, consensusAPI.HeightLatest, quantity.NewQuantity())
			assertAccountBalance(t, consensus, submitterAddr, ev.Height, testState.submitterBalance)

			// Test proposals query.
			proposals, err := backend.Proposals(ctx, consensusAPI.HeightLatest)
			require.NoError(err, "Proposals query")
			require.True(len(proposals) > 1, "At least two proposals should exist")
			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive event")
		}
	}
}
