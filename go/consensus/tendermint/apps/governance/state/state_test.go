package state

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func descriptor(epoch beacon.EpochTime, target version.ProtocolVersions) upgrade.Descriptor {
	return upgrade.Descriptor{
		Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
		Handler:   "base",
		Target:    target,
		Epoch:     epoch,
	}
}

func initProposals(require *require.Assertions, ctx *abciAPI.Context, s *MutableState) []*governance.Proposal {
	fac := memorySigner.NewFactory()

	// Generate Submitter Account.
	submitter, err := fac.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "generating submitter signer")
	submitterAddr := staking.NewAddress(submitter.Public())

	proposals := []*governance.Proposal{
		{
			Submitter: submitterAddr,
			State:     governance.StateActive,
			ClosesAt:  beacon.EpochTime(10),
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: descriptor(100, version.ProtocolVersions{ConsensusProtocol: version.FromU64(1)}),
				},
			},
			CreatedAt: beacon.EpochTime(1),
			Deposit:   *quantity.NewFromUint64(10),
		},
		{
			Submitter: submitterAddr,
			State:     governance.StateActive,
			ClosesAt:  beacon.EpochTime(20),
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: descriptor(200, version.ProtocolVersions{ConsensusProtocol: version.FromU64(2)}),
				},
			},
			CreatedAt: beacon.EpochTime(11),
			Deposit:   *quantity.NewFromUint64(100),
		},
		{
			Submitter: submitterAddr,
			State:     governance.StateActive,
			ClosesAt:  beacon.EpochTime(30),
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: descriptor(300, version.ProtocolVersions{ConsensusProtocol: version.FromU64(3)}),
				},
			},
			CreatedAt: beacon.EpochTime(21),
			Deposit:   *quantity.NewFromUint64(100),
		},
		{
			Submitter: submitterAddr,
			State:     governance.StateActive,
			ClosesAt:  beacon.EpochTime(30),
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: descriptor(300, version.ProtocolVersions{ConsensusProtocol: version.FromU64(4)}),
				},
			},
			CreatedAt: beacon.EpochTime(21),
			Deposit:   *quantity.NewFromUint64(100),
		},
		{
			Submitter: submitterAddr,
			State:     governance.StateActive,
			ClosesAt:  beacon.EpochTime(40),
			Content: governance.ProposalContent{
				CancelUpgrade: &governance.CancelUpgradeProposal{
					ProposalID: 0,
				},
			},
			CreatedAt: beacon.EpochTime(31),
			Deposit:   *quantity.NewFromUint64(100),
		},
	}
	for _, proposal := range proposals {
		var id uint64
		id, err = s.NextProposalIdentifier(ctx)
		require.NoError(err, "NextProposalIdentifier")

		proposal.ID = id
		err = s.SetActiveProposal(ctx, proposal)
		require.NoError(err, "SetActiveProposal")

		err = s.SetNextProposalIdentifier(ctx, id+1)
		require.NoError(err, "SetNextProposalIdentifier")
	}

	return proposals
}

func TestProposals(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	proposals := initProposals(require, ctx, s)

	// All proposals should be inserted.
	qProposals, err := s.Proposals(ctx)
	require.NoError(err, "Proposals")
	require.ElementsMatch(qProposals, proposals, "Proposals should return all proposals.")

	activeProposals, err := s.ActiveProposals(ctx)
	require.NoError(err, "ActiveProposals")
	require.ElementsMatch(activeProposals, proposals, "ActiveProposals should return all active proposals.")

	id, err := s.NextProposalIdentifier(ctx)
	require.NoError(err, "NextProposalIdentifier")
	require.EqualValues(len(proposals), id, "NextProposalIdentifier should be the expected value")

	for _, p1 := range proposals {
		var p2 *governance.Proposal
		p2, err = s.Proposal(ctx, p1.ID)
		require.NoError(err, "Proposal()")
		require.Equal(p1, p2, "Queried proposal should match inserted one")

		// Lookup votes for the proposal.
		var votes []*governance.VoteEntry
		votes, err = s.Votes(ctx, p1.ID)
		require.NoError(err, "Votes()")
		require.Empty(votes, "There should be no votes.")
	}

	// Remove active proposal.
	closedProposal := proposals[0]
	closedProposal.State = governance.StatePassed
	err = s.SetProposal(ctx, closedProposal)
	require.NoError(err, "Update proposal")

	err = s.RemoveActiveProposal(ctx, closedProposal)
	require.NoError(err, "RemoveActiveProposal()")

	// Active proposals should not include the closed proposal.
	expectedActiveProposals := proposals[1:]
	activeProposals, err = s.ActiveProposals(ctx)
	require.NoError(err, "ActiveProposals")
	require.ElementsMatch(activeProposals, expectedActiveProposals, "ActiveProposals should return all active proposals.")

	// Proposals should include also closed proposals.
	qProposals, err = s.Proposals(ctx)
	require.NoError(err, "Proposals")
	require.ElementsMatch(qProposals, proposals, "Proposals should return all proposals.")

	// Querying closed proposal should still work.
	var p *governance.Proposal
	p, err = s.Proposal(ctx, closedProposal.ID)
	require.NoError(err, "Proposal()")
	require.Equal(closedProposal, p, "Queried proposal should match inserted one")
}

func TestVotes(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	proposals := initProposals(require, ctx, s)

	var voterAddrs []staking.Address
	fac := memorySigner.NewFactory()
	for i := 0; i < 3; i++ {
		acc, err := fac.Generate(signature.SignerEntity, rand.Reader)
		require.NoError(err, "generating signer")
		voterAddrs = append(voterAddrs, staking.NewAddress(acc.Public()))
	}

	// Add some votes.
	err := s.SetVote(ctx, proposals[0].ID, voterAddrs[0], governance.VoteYes)
	require.NoError(err, "SetVote()")
	err = s.SetVote(ctx, proposals[0].ID, voterAddrs[1], governance.VoteNo)
	require.NoError(err, "SetVote()")
	err = s.SetVote(ctx, proposals[0].ID, voterAddrs[2], governance.VoteAbstain)
	require.NoError(err, "SetVote()")

	err = s.SetVote(ctx, proposals[1].ID, voterAddrs[0], governance.VoteNo)
	require.NoError(err, "SetVote()")
	err = s.SetVote(ctx, proposals[2].ID, voterAddrs[0], governance.VoteAbstain)
	require.NoError(err, "SetVote()")
	err = s.SetVote(ctx, proposals[3].ID, voterAddrs[0], governance.VoteYes)
	require.NoError(err, "SetVote()")

	expectedVote0Entries := []*governance.VoteEntry{
		{Voter: voterAddrs[0], Vote: governance.VoteYes},
		{Voter: voterAddrs[1], Vote: governance.VoteNo},
		{Voter: voterAddrs[2], Vote: governance.VoteAbstain},
	}
	expectedVote1Entries := []*governance.VoteEntry{
		{Voter: voterAddrs[0], Vote: governance.VoteNo},
	}
	expectedVote2Entries := []*governance.VoteEntry{
		{Voter: voterAddrs[0], Vote: governance.VoteAbstain},
	}
	expectedVote3Entries := []*governance.VoteEntry{
		{Voter: voterAddrs[0], Vote: governance.VoteYes},
	}
	// Query votes.
	votes0, err := s.Votes(ctx, proposals[0].ID)
	require.NoError(err, "Votes()")
	require.ElementsMatch(votes0, expectedVote0Entries, "Vote entries should match")

	votes1, err := s.Votes(ctx, proposals[1].ID)
	require.NoError(err, "Votes()")
	require.ElementsMatch(votes1, expectedVote1Entries, "Vote entries should match")

	votes2, err := s.Votes(ctx, proposals[2].ID)
	require.NoError(err, "Votes()")
	require.ElementsMatch(votes2, expectedVote2Entries, "Vote entries should match")

	votes3, err := s.Votes(ctx, proposals[3].ID)
	require.NoError(err, "Votes()")
	require.ElementsMatch(votes3, expectedVote3Entries, "Vote entries should match")

	// Override vote.
	err = s.SetVote(ctx, proposals[0].ID, voterAddrs[2], governance.VoteYes)
	require.NoError(err, "SetVote()")
	expectedVote0Entries[2] = &governance.VoteEntry{Voter: voterAddrs[2], Vote: governance.VoteYes}

	// Query votes.
	votes0, err = s.Votes(ctx, proposals[0].ID)
	require.NoError(err, "Votes()")
	require.ElementsMatch(votes0, expectedVote0Entries, "Vote entries should match after update")
}

func TestPendingUpgrades(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	proposals := initProposals(require, ctx, s)

	var expectedPendingUpgrades []*upgrade.Descriptor
	// Add Pending upgrades.
	for _, proposal := range proposals {
		if proposal.Content.Upgrade == nil {
			continue
		}
		err := s.SetPendingUpgrade(ctx, proposal.ID, &proposal.Content.Upgrade.Descriptor)
		require.NoError(err, "SetPendingUpgrade()")
		expectedPendingUpgrades = append(expectedPendingUpgrades, &proposal.Content.Upgrade.Descriptor)
	}

	pendingUpgrades, err := s.PendingUpgrades(ctx)
	require.NoError(err, "PendingUpgrades()")
	require.ElementsMatch(pendingUpgrades, expectedPendingUpgrades, "Pending upgrades should match")

	// Test querying pending upgrade proposals.
	for _, proposal := range proposals {
		var upgradeProposal *governance.UpgradeProposal
		switch {
		case proposal.Content.Upgrade != nil:
			upgradeProposal, err = s.PendingUpgradeProposal(ctx, proposal.ID)
			require.NoError(err, "PendingUpgradeProposal()")
			require.Equal(proposal.Content.Upgrade, upgradeProposal, "PendingUpgradeProposal should match")

		case proposal.Content.CancelUpgrade != nil:
			upgradeProposal, err = s.PendingUpgradeProposal(ctx, proposal.ID)
			require.EqualError(err, governance.ErrNoSuchUpgrade.Error(), "PendingUpgradeProposal should error for cancel upgrade proposals")
			require.Nil(upgradeProposal, "PendingUpgradeProposal for cancel upgrade")
		}
	}

	// Remove pending upgrade.
	err = s.RemovePendingUpgrade(ctx, expectedPendingUpgrades[0].Epoch, proposals[0].ID)
	require.NoError(err, "RemovePendingUpgrade()")
	upgradeProposal, err := s.PendingUpgradeProposal(ctx, proposals[0].ID)
	require.EqualError(err, governance.ErrNoSuchUpgrade.Error(), "PendingUpgradeProposal should error for removed pending upgrade")
	require.Nil(upgradeProposal, "PendingUpgradeProposal for removed upgrade")
	expectedPendingUpgrades = expectedPendingUpgrades[1:]

	// Remove pending upgrades for epoch.
	removedEpoch := expectedPendingUpgrades[len(expectedPendingUpgrades)-1].Epoch
	err = s.RemovePendingUpgradesForEpoch(ctx, removedEpoch)
	require.NoError(err, "RemovePendingUpgradesForEpoch()")

	var newExpectedPendingUpgrades []*upgrade.Descriptor
	for _, expected := range expectedPendingUpgrades {
		if expected.Epoch == removedEpoch {
			// Pending upgrades for this epoch were removed.
			continue
		}
		newExpectedPendingUpgrades = append(newExpectedPendingUpgrades, expected)
	}
	pendingUpgrades, err = s.PendingUpgrades(ctx)
	require.NoError(err, "PendingUpgrades()")
	require.ElementsMatch(pendingUpgrades, newExpectedPendingUpgrades, "Pending upgrades should match")
}
