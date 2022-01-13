package governance

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	"github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func baseAtEpoch(epoch beacon.EpochTime) upgrade.Descriptor {
	return upgrade.Descriptor{
		Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
		Handler:   "base",
		Target:    version.Versions,
		Epoch:     epoch,
	}
}

func TestInitChain(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{
		BaseEpoch:    1,
		CurrentEpoch: 80,
	})
	ctx := appState.NewContext(abciAPI.ContextInitChain, now)
	defer ctx.Close()

	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}

	// Prepare some test staking addresses.
	var addresses []staking.Address
	for i := 0; i < 5; i++ {
		pk := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance/genesis_test: %d", i)).Public()
		addresses = append(addresses, staking.NewAddress(pk))
	}

	voteEntries := map[uint64][]*governance.VoteEntry{
		1: {{Voter: addresses[0], Vote: governance.VoteNo}, {Voter: addresses[1], Vote: governance.VoteNo}},
		2: {{Voter: addresses[0], Vote: governance.VoteYes}, {Voter: addresses[1], Vote: governance.VoteYes}},
		// No vote entries for 3 - doesn't matter already closed proposal.
		4: {{Voter: addresses[1], Vote: governance.VoteYes}, {Voter: addresses[2], Vote: governance.VoteNo}},
		5: {{Voter: addresses[4], Vote: governance.VoteYes}, {Voter: addresses[3], Vote: governance.VoteYes}},
	}

	for _, tc := range []struct {
		msg        string
		genesisDoc *api.Document
		check      func()
	}{
		{
			"should correctly initialize empty state",
			&api.Document{Governance: governance.Genesis{}},
			func() {
				var nextProposalID uint64
				nextProposalID, err = state.NextProposalIdentifier(ctx)
				require.NoError(err, "NextProposalIdentifier")
				require.EqualValues(1, nextProposalID, "next proposal identifier should be expected")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals")
				require.Empty(proposals, "no proposals should exist")

				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Empty(pendingUpgrades, "no pending upgrades should exist")
			},
		},
		{
			"should correctly initialize state",
			&api.Document{Governance: governance.Genesis{
				Proposals: []*governance.Proposal{
					// Closed rejected proposal.
					{
						ID:           1,
						ClosesAt:     20,
						State:        governance.StateRejected,
						InvalidVotes: 3,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(1),
							},
						},
						CreatedAt: 10,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[0],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteNo: *quantity.NewFromUint64(10),
						},
					},
					// Closed accepted proposal with upgrade in past.
					{
						ID:           2,
						ClosesAt:     20,
						State:        governance.StatePassed,
						InvalidVotes: 0,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(30),
							},
						},
						CreatedAt: 10,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[1],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
					// Closed accepted cancel upgrade proposal.
					{
						ID:           3,
						ClosesAt:     20,
						State:        governance.StatePassed,
						InvalidVotes: 3,
						Content:      governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 2}},
						CreatedAt:    10,
						Deposit:      *quantity.NewFromUint64(10),
						Submitter:    addresses[2],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
					// Open proposal with some votes.
					{
						ID:           4,
						ClosesAt:     100,
						State:        governance.StateActive,
						InvalidVotes: 0,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(10000),
							},
						},
						CreatedAt: 20,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[3],
					},
					// Closed accepted upgrade proposal.
					{
						ID:           5,
						ClosesAt:     70,
						State:        governance.StatePassed,
						InvalidVotes: 0,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(1000),
							},
						},
						CreatedAt: 20,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[4],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
					// Closed accepted upgrade proposal.
					{
						ID:           6,
						ClosesAt:     70,
						State:        governance.StatePassed,
						InvalidVotes: 0,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(2000),
							},
						},
						CreatedAt: 60,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[4],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
					// Closed accepted canceled upgrade proposal.
					{
						ID:           7,
						ClosesAt:     70,
						State:        governance.StatePassed,
						InvalidVotes: 0,
						Content: governance.ProposalContent{
							Upgrade: &governance.UpgradeProposal{
								Descriptor: baseAtEpoch(2000),
							},
						},
						CreatedAt: 60,
						Deposit:   *quantity.NewFromUint64(10),
						Submitter: addresses[4],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
					// Cancel previous proposal.
					{
						ID:           8,
						ClosesAt:     80,
						State:        governance.StatePassed,
						InvalidVotes: 0,
						Content:      governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 7}},
						CreatedAt:    60,
						Deposit:      *quantity.NewFromUint64(10),
						Submitter:    addresses[4],
						Results: map[governance.Vote]quantity.Quantity{
							governance.VoteYes: *quantity.NewFromUint64(10),
						},
					},
				},
				VoteEntries: voteEntries,
			}},
			func() {
				var nextProposalID uint64
				nextProposalID, err = state.NextProposalIdentifier(ctx)
				require.NoError(err, "NextProposalIdentifier")
				require.EqualValues(9, nextProposalID, "next proposal identifier should be expected")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals")
				require.Len(proposals, 8, "all proposals should exist")

				var activeProposals []*governance.Proposal
				activeProposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "ActiveProposals")
				require.Len(activeProposals, 1, "one proposal should be active")
				require.EqualValues(4, activeProposals[0].ID, "active proposal should match")

				var votes []*governance.VoteEntry
				votes, err = state.Votes(ctx, 1)
				require.ElementsMatch(voteEntries[1], votes, "votes for proposal 1 should match")

				votes, err = state.Votes(ctx, 2)
				require.ElementsMatch(voteEntries[2], votes, "votes for proposal 2 should match")

				votes, err = state.Votes(ctx, 3)
				require.Empty(votes, "no votes for proposal 3")

				votes, err = state.Votes(ctx, 4)
				require.ElementsMatch(voteEntries[4], votes, "votes for proposal 4 should match")

				votes, err = state.Votes(ctx, 5)
				require.ElementsMatch(voteEntries[5], votes, "votes for proposal 5 should match")

				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(pendingUpgrades, 2, "there should be two pending upgrades")
				require.EqualValues(1000, pendingUpgrades[0].Epoch, "pending upgrade epochs should natch")
				require.EqualValues(2000, pendingUpgrades[1].Epoch, "pending upgrade epochs should match")
			},
		},
	} {
		err = app.InitChain(ctx, types.RequestInitChain{}, tc.genesisDoc)
		require.NoError(err, tc.msg)
		tc.check()
	}
}

func TestGenesis(t *testing.T) {
	require := require.New(t)
	var err error
	currentEpoch := beacon.EpochTime(80)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{
		BlockHeight:  1000,
		BaseEpoch:    1,
		CurrentEpoch: currentEpoch,
	})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	state := governanceState.NewMutableState(ctx.State())

	// Prepare some test staking addresses.
	var addresses []staking.Address
	for i := 0; i < 5; i++ {
		pk := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance/genesis_test: %d", i)).Public()
		addresses = append(addresses, staking.NewAddress(pk))
	}

	// Prepare testing values.
	consensusParams := &governance.ConsensusParameters{
		GasCosts:                  governance.DefaultGasCosts,
		MinProposalDeposit:        *quantity.NewFromUint64(42),
		StakeThreshold:            90,
		UpgradeCancelMinEpochDiff: beacon.EpochTime(100),
		UpgradeMinEpochDiff:       beacon.EpochTime(100),
		VotingPeriod:              beacon.EpochTime(50),
	}
	proposals := []*governance.Proposal{
		// Closed rejected proposal.
		{
			ID:           1,
			ClosesAt:     20,
			State:        governance.StateRejected,
			InvalidVotes: 3,
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: baseAtEpoch(30),
				},
			},
			CreatedAt: 10,
			Deposit:   *quantity.NewFromUint64(10),
			Submitter: addresses[0],
			Results: map[governance.Vote]quantity.Quantity{
				governance.VoteNo: *quantity.NewFromUint64(10),
			},
		},
		// Closed accepted proposal with upgrade in past.
		{
			ID:           2,
			ClosesAt:     20,
			State:        governance.StatePassed,
			InvalidVotes: 0,
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: baseAtEpoch(30),
				},
			},
			CreatedAt: 10,
			Deposit:   *quantity.NewFromUint64(10),
			Submitter: addresses[1],
			Results: map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(10),
			},
		},
		// Closed accepted cancel upgrade proposal.
		{
			ID:           3,
			ClosesAt:     20,
			State:        governance.StatePassed,
			InvalidVotes: 3,
			Content:      governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 2}},
			CreatedAt:    10,
			Deposit:      *quantity.NewFromUint64(10),
			Submitter:    addresses[2],
			Results: map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(10),
			},
		},
		// Open proposal with some votes.
		{
			ID:           4,
			ClosesAt:     100,
			State:        governance.StateActive,
			InvalidVotes: 0,
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: baseAtEpoch(10000),
				},
			},
			CreatedAt: 20,
			Deposit:   *quantity.NewFromUint64(10),
			Submitter: addresses[3],
		},
		// Closed accepted upgrade proposal.
		{
			ID:           5,
			ClosesAt:     100,
			State:        governance.StatePassed,
			InvalidVotes: 0,
			Content: governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: baseAtEpoch(10000),
			}},
			CreatedAt: 20,
			Deposit:   *quantity.NewFromUint64(10),
			Submitter: addresses[4],
			Results: map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(10),
			},
		},
	}
	voteEntries := map[uint64][]*governance.VoteEntry{
		1: {{Voter: addresses[0], Vote: governance.VoteNo}, {Voter: addresses[1], Vote: governance.VoteNo}},
		2: {{Voter: addresses[0], Vote: governance.VoteYes}, {Voter: addresses[1], Vote: governance.VoteYes}},
		3: nil, // No vote entries for 3 - doesn't matter already closed proposal.
		4: {{Voter: addresses[1], Vote: governance.VoteYes}, {Voter: addresses[2], Vote: governance.VoteNo}},
		5: {{Voter: addresses[4], Vote: governance.VoteYes}, {Voter: addresses[3], Vote: governance.VoteYes}},
	}

	for _, tc := range []struct {
		msg             string
		init            func()
		expectedGenesis governance.Genesis
	}{
		{
			"should correctly export genesis from empty state",
			func() {
				err = state.SetConsensusParameters(ctx, &governance.ConsensusParameters{})
				require.NoError(err, "ConsensusParameters")
			},
			governance.Genesis{
				VoteEntries: make(map[uint64][]*governance.VoteEntry),
			},
		},
		{
			"should correctly export genesis",
			func() {
				// Prepare state that should be exported into the expected genesis.
				err = state.SetConsensusParameters(ctx, consensusParams)
				require.NoError(err, "ConsensusParameters")

				err = state.SetNextProposalIdentifier(ctx, 42)
				require.NoError(err, "SetNextProposalIdentifier")

				for _, p := range proposals {
					switch p.State {
					case governance.StateActive:
						err = state.SetActiveProposal(ctx, p)
						require.NoError(err, "SetActiveProposal")
					case governance.StatePassed:
						if p.Content.Upgrade != nil && p.Content.Upgrade.Descriptor.Epoch > currentEpoch {
							err = state.SetPendingUpgrade(ctx, p.ID, &p.Content.Upgrade.Descriptor)
							require.NoError(err, "SetPendingUpgrade")
						}
						fallthrough
					default:
						err = state.SetProposal(ctx, p)
						require.NoError(err, "SetProposal")
					}
				}

				for pid, vs := range voteEntries {
					for _, v := range vs {
						err = state.SetVote(ctx, pid, v.Voter, v.Vote)
						require.NoError(err, "SetVote")
					}
				}
			},
			governance.Genesis{
				Parameters:  *consensusParams,
				Proposals:   proposals,
				VoteEntries: voteEntries,
			},
		},
	} {
		tc.init()

		qf := NewQueryFactory(appState)
		var q Query
		// Need to use blockHeight+1, so that request is treated like it was
		// made from an ABCI application context.
		q, err = qf.QueryAt(ctx, 1001)
		require.NoError(err, "QueryAt")

		var g *governance.Genesis
		g, err = q.Genesis(ctx)
		require.NoError(err, tc.msg)

		require.EqualValues(tc.expectedGenesis.Parameters, g.Parameters, tc.msg)
		require.ElementsMatch(tc.expectedGenesis.Proposals, g.Proposals, tc.msg)

		// Ensure votes match.
		require.Len(g.VoteEntries, len(tc.expectedGenesis.VoteEntries), tc.msg)
		for _, p := range tc.expectedGenesis.Proposals {
			require.ElementsMatch(tc.expectedGenesis.VoteEntries[p.ID], g.VoteEntries[p.ID], tc.msg)
		}
	}
}
