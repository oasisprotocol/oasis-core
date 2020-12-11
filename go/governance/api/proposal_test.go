package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func TestProposalState(t *testing.T) {
	require := require.New(t)

	// Test valid states.
	for _, p := range []ProposalState{
		StateActive,
		StateFailed,
		StatePassed,
		StateRejected,
	} {
		enc, err := p.MarshalText()
		require.NoError(err, "MarshalText")

		var s ProposalState
		err = s.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")
		require.Equal(p, s, "proposal state should round-trip")

		require.EqualValues([]byte(p.String()), enc, "marshalled proposal state should match")
	}

	// Test invalid state.
	p := ProposalState(0)
	_, err := p.MarshalText()
	require.Error(err, "MarshalText on invalid proposal state")
	require.Contains(p.String(), "unknown state", "String() on invalid proposal state")

	var s ProposalState
	err = s.UnmarshalText([]byte{})
	require.Error(err, "unmarshal on invalid proposal state")
}

func TestVote(t *testing.T) {
	require := require.New(t)

	// Test valid votes.
	for _, v := range []Vote{
		VoteYes,
		VoteNo,
		VoteAbstain,
	} {
		enc, err := v.MarshalText()
		require.NoError(err, "MarshalText")

		var vt Vote
		err = vt.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")
		require.Equal(v, vt, "vote should round-trip")
		require.EqualValues([]byte(vt.String()), enc, "marshalled vote should match")
	}

	// Test invalid vote.
	v := Vote(0)
	_, err := v.MarshalText()
	require.Error(err, "MarshalText on invalid vote")
	require.Contains(v.String(), "unknown vote", "String() on invalid vote")

	var vt Vote
	err = vt.UnmarshalText([]byte{})
	require.Error(err, "unmarshal on invalid vote")
}

func TestVotedSum(t *testing.T) {
	for _, tc := range []struct {
		msg      string
		p        *Proposal
		expected *quantity.Quantity
	}{
		{
			msg:      "empty results should be 0",
			p:        &Proposal{},
			expected: quantity.NewFromUint64(0),
		},
		{
			msg: "results sum should match",
			p: &Proposal{
				Results: map[Vote]quantity.Quantity{
					VoteNo:      *quantity.NewFromUint64(1),
					VoteYes:     *quantity.NewFromUint64(7),
					VoteAbstain: *quantity.NewFromUint64(13),
				},
			},
			expected: quantity.NewFromUint64(21),
		},
	} {
		res, err := tc.p.VotedSum()
		require.NoError(t, err, tc.msg)
		require.EqualValues(t, 0, res.Cmp(tc.expected))
	}
}

func TestCloseProposal(t *testing.T) {
	totalVotingStake := quantity.NewFromUint64(100)
	for _, tc := range []struct {
		msg string

		p                *Proposal
		totalVotingStake *quantity.Quantity
		quorum           uint8
		threshold        uint8

		expectedState ProposalState
		expectedErr   error
	}{
		{
			msg: "proposal in invalid state",
			p: &Proposal{
				State: StateFailed,
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "invalid total voting stake",
			p: &Proposal{
				State: StateActive,
			},
			totalVotingStake: quantity.NewFromUint64(0),
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal without results",
			p: &Proposal{
				State: StateActive,
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal with empty results",
			p: &Proposal{
				State:   StateActive,
				Results: map[Vote]quantity.Quantity{},
			},
			totalVotingStake: totalVotingStake,
			expectedState:    StateRejected,
		},
		{
			msg: "proposal quotum not reached",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					// 100% of votes Yes, but quorum is only 80%.
					VoteYes: *quantity.NewFromUint64(80),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StateRejected,
		},
		{
			msg: "proposal threshold not reached",
			p: &Proposal{
				State: StateActive,
				// Quorum reached, but threshold not reached.
				Results: map[Vote]quantity.Quantity{
					VoteYes:     *quantity.NewFromUint64(55),
					VoteNo:      *quantity.NewFromUint64(40),
					VoteAbstain: *quantity.NewFromUint64(1),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StateRejected,
		},
		{
			msg: "more votes than possible",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					VoteYes: *quantity.NewFromUint64(200),
				},
			},
			totalVotingStake: totalVotingStake,
			expectedErr:      errInvalidProposalState,
		},
		{
			msg: "proposal of all Vote yes should pass",
			p: &Proposal{
				State: StateActive,
				Results: map[Vote]quantity.Quantity{
					VoteYes: *quantity.NewFromUint64(100),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           100,
			threshold:        100,
			expectedState:    StatePassed,
		},
		{
			msg: "proposal should pass",
			p: &Proposal{
				State: StateActive,
				// Quorum and threshold reached.
				// Quorum: 91/100: 91%
				// Threshold: 85/91: ~93%
				Results: map[Vote]quantity.Quantity{
					VoteYes:     *quantity.NewFromUint64(85),
					VoteNo:      *quantity.NewFromUint64(3),
					VoteAbstain: *quantity.NewFromUint64(3),
				},
			},
			totalVotingStake: totalVotingStake,
			quorum:           90,
			threshold:        90,
			expectedState:    StatePassed,
		},
	} {
		err := tc.p.CloseProposal(*tc.totalVotingStake, tc.quorum, tc.threshold)
		if tc.expectedErr != nil {
			require.True(t, errors.Is(err, tc.expectedErr),
				fmt.Sprintf("expected error: %v, got: %v: for case: %s", tc.expectedErr, err, tc.msg))
			continue
		}
		require.NoError(t, err, tc.msg)
		require.Equal(t, tc.expectedState, tc.p.State, tc.msg)
	}
}

// Applies test on all permutations of the proposal list.
func testPerms(a []*Proposal, test func([]*Proposal), i int) {
	if i > len(a) {
		test(a)
		return
	}
	testPerms(a, test, i+1)
	for j := i + 1; j < len(a); j++ {
		a[i], a[j] = a[j], a[i]
		testPerms(a, test, i+1)
		a[i], a[j] = a[j], a[i]
	}
}

func TestPendingUpgradesFromProposals(t *testing.T) {
	epoch := epochtime.EpochTime(20)
	proposals := []*Proposal{
		// Passed but in past, so should not be present among proposals.
		{
			ID:    1,
			State: StatePassed,
			Content: ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{
						Name:  "in past",
						Epoch: epochtime.EpochTime(10),
					},
				},
			},
		},
		// Passed but will be canceled.
		{
			ID:    2,
			State: StatePassed,
			Content: ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{
						Name:  "canceled",
						Epoch: epochtime.EpochTime(30),
					},
				},
			},
		},
		// Not passed state.
		{
			ID:    3,
			State: StateActive,
			Content: ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{
						Name:  "not passed",
						Epoch: epochtime.EpochTime(30),
					},
				},
			},
		},
		// Passed - should be present among pending upgrades.
		{
			ID:    4,
			State: StatePassed,
			Content: ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{
						Name:  "passed",
						Epoch: epochtime.EpochTime(40),
					},
				},
			},
		},
		// Passed - should be present among pending upgrades.
		{
			ID:    5,
			State: StatePassed,
			Content: ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{
						Name:  "passed2",
						Epoch: epochtime.EpochTime(50),
					},
				},
			},
		},
		// Passed cancel proposal for ID: 2.
		{
			ID:    6,
			State: StatePassed,
			Content: ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{
					ProposalID: 2,
				},
			},
		},
		// Rejected cancel proposal for ID: 4.
		{
			ID:    7,
			State: StateRejected,
			Content: ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{
					ProposalID: 4,
				},
			},
		},
	}
	expectedProposalIDs := []uint64{4, 5}
	expectedDescriptors := []*upgrade.Descriptor{
		&proposals[3].Content.Upgrade.Descriptor,
		&proposals[4].Content.Upgrade.Descriptor,
	}

	// Test all permutations - order shouldn't affect results.
	testPerms(proposals, func(p []*Proposal) {
		pendingUpgrades, ids := PendingUpgradesFromProposals(p, epoch)
		require.ElementsMatch(t, expectedProposalIDs, ids, "proposal IDs should match")
		require.ElementsMatch(t, expectedDescriptors, pendingUpgrades, "pending upgrades should match")
	}, 0)
}
