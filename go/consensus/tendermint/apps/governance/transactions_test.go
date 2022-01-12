package governance

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestSubmitProposal(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup staking state.
	stakeState := stakingState.NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	noFundsPk := signature.NewPublicKey("f00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	reservedPK := signature.NewPublicKey("badaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = staking.NewReservedAddress(reservedPK)

	// Configure a balance for pk1.
	err = stakeState.SetAccount(ctx, addr1, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(400),
		},
	})
	require.NoError(err, "SetAccount")

	// Setup governance state.
	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}

	minProposalDeposit := quantity.NewFromUint64(100)
	baseConsParams := &governance.ConsensusParameters{
		GasCosts:                  governance.DefaultGasCosts,
		MinProposalDeposit:        *minProposalDeposit,
		StakeThreshold:            90,
		UpgradeCancelMinEpochDiff: beacon.EpochTime(100),
		UpgradeMinEpochDiff:       beacon.EpochTime(100),
		VotingPeriod:              beacon.EpochTime(50),
	}

	for _, tc := range []struct {
		msg             string
		params          *governance.ConsensusParameters
		txSigner        signature.PublicKey
		proposalContent *governance.ProposalContent
		prepareFn       func()
		err             error
	}{
		{
			"should fail with malformed proposal content",
			baseConsParams,
			pk1,
			&governance.ProposalContent{},
			func() {},
			governance.ErrInvalidArgument,
		},
		{
			"should fail with reserved submitter address",
			baseConsParams,
			reservedPK,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: baseAtEpoch(10),
			}},
			func() {},
			staking.ErrForbidden,
		},
		{
			"should fail with insufficient submitter balance",
			baseConsParams,
			noFundsPk,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: baseAtEpoch(10),
			}},
			func() {},
			staking.ErrInsufficientBalance,
		},
		{
			"should fail with invalid upgrade proposal",
			baseConsParams,
			pk1,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{}},
			func() {},
			governance.ErrInvalidArgument,
		},
		{
			"should fail with valid upgrade proposal scheduled for to soon",
			baseConsParams,
			pk1,
			&governance.ProposalContent{Upgrade: &governance.UpgradeProposal{
				Descriptor: baseAtEpoch(10),
			}},
			func() {},
			governance.ErrUpgradeTooSoon,
		},
		{
			"should fail cancel upgrade proposal for non-existing pending upgrade",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 10,
			}},
			func() {},
			governance.ErrNoSuchProposal,
		},
		{
			"should fail cancel upgrade proposal for pending upgrade scheduled to soon",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 10,
			}},
			func() {
				upgrade := baseAtEpoch(10)
				err = state.SetPendingUpgrade(ctx, 10, &upgrade)
				require.NoError(err, "SetPendingUpgrade()")
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 10,
					Content: governance.ProposalContent{
						Upgrade: &governance.UpgradeProposal{
							Descriptor: upgrade,
						},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			governance.ErrUpgradeTooSoon,
		},
		{
			"should work with valid upgrade descriptor",
			baseConsParams,
			pk1,
			&governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: baseAtEpoch(200),
				},
			},
			func() {},
			nil,
		},
		{
			"should work with valid cancel upgrade proposal",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 20,
			}},
			func() {
				upgrade := baseAtEpoch(500)
				err = state.SetPendingUpgrade(ctx, 20, &upgrade)
				require.NoError(err, "SetPendingUpgrade()")
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 20,
					Content: governance.ProposalContent{
						Upgrade: &governance.UpgradeProposal{
							Descriptor: upgrade,
						},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			nil,
		},
		{
			"should fail cancel upgrade proposal for a cancel upgrade proposal",
			baseConsParams,
			pk1,
			&governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{
				ProposalID: 40,
			}},
			func() {
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 40,
					Content: governance.ProposalContent{
						CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 20},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			governance.ErrNoSuchUpgrade,
		},
		{
			"should fail submit upgrade proposal for pending upgrade scheduled close",
			baseConsParams,
			pk1,
			&governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: baseAtEpoch(210),
				},
			},
			func() {
				upgrade := baseAtEpoch(200)
				err = state.SetPendingUpgrade(ctx, 10, &upgrade)
				require.NoError(err, "SetPendingUpgrade()")
				err = state.SetProposal(ctx, &governance.Proposal{
					ID: 10,
					Content: governance.ProposalContent{
						Upgrade: &governance.UpgradeProposal{
							Descriptor: upgrade,
						},
					},
				})
				require.NoError(err, "SetProposal()")
			},
			governance.ErrUpgradeAlreadyPending,
		},
	} {
		err = state.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting governance consensus parameters should not error")

		txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
		defer txCtx.Close()
		txCtx.SetTxSigner(tc.txSigner)

		tc.prepareFn()

		var governanceDepositsBefore, governanceDepositsAfter *quantity.Quantity
		governanceDepositsBefore, err = stakeState.GovernanceDeposits(txCtx)
		require.NoError(err, "GovernanceDeposits()")

		err = app.submitProposal(txCtx, state, tc.proposalContent)
		if tc.err != nil {
			require.True(errors.Is(err, tc.err), tc.msg)
			continue
		}

		// If proposal passed, ensure proposal deposit was made.
		governanceDepositsAfter, err = stakeState.GovernanceDeposits(txCtx)
		require.NoError(err, "GovernanceDeposits()")

		err = governanceDepositsAfter.Sub(governanceDepositsBefore)
		require.NoError(err, "quantity.Sub")
		require.EqualValues(&tc.params.MinProposalDeposit, governanceDepositsAfter, tc.msg)
	}
}

func TestCastVote(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup state.
	registryState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())
	schedulerState := schedulerState.NewMutableState(ctx.State())
	signers, addresses, _ := initValidatorsEscrowState(t, stakeState, registryState, schedulerState)
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	reservedPK := signature.NewPublicKey("badbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = staking.NewReservedAddress(reservedPK)

	// Setup governance state.
	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}
	params := &governance.ConsensusParameters{
		GasCosts:                  governance.DefaultGasCosts,
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		StakeThreshold:            90,
		UpgradeCancelMinEpochDiff: beacon.EpochTime(100),
		UpgradeMinEpochDiff:       beacon.EpochTime(100),
		VotingPeriod:              beacon.EpochTime(50),
	}
	err = state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting governance consensus parameters should not error")

	p1 := &governance.Proposal{ID: 1, State: governance.StateActive}
	err = state.SetActiveProposal(ctx, p1)
	require.NoError(err, "SetActiveProposal")
	p2 := &governance.Proposal{ID: 2, State: governance.StateRejected}
	err = state.SetProposal(ctx, p2)
	require.NoError(err, "SetProposal")

	for _, tc := range []struct {
		msg      string
		txSigner signature.PublicKey
		vote     *governance.ProposalVote
		err      error
		check    func()
	}{
		{
			"should fail with malformed vote content",
			signers[1].Public(),
			&governance.ProposalVote{},
			governance.ErrNoSuchProposal,
			func() {},
		},
		{
			"should fail with reserved signer",
			reservedPK,
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteYes,
			},
			staking.ErrForbidden,
			func() {},
		},
		{
			"should fail with an invalid signer",
			pk1,
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteYes,
			},
			governance.ErrNotEligible,
			func() {},
		},
		{
			"should fail with if submitter not a validator",
			signers[0].Public(),
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteYes,
			},
			governance.ErrNotEligible,
			func() {},
		},
		{
			"should fail for missing proposals",
			signers[1].Public(),
			&governance.ProposalVote{ID: 99},
			governance.ErrNoSuchProposal,
			func() {},
		},
		{
			"should fail for closed proposals",
			signers[1].Public(),
			&governance.ProposalVote{
				ID:   p2.ID,
				Vote: governance.VoteYes,
			},
			governance.ErrVotingIsClosed,
			func() {},
		},
		{
			"should work",
			signers[1].Public(),
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteYes,
			},
			nil,
			func() {
				// Ensure vote exists.
				var votes []*governance.VoteEntry
				votes, err = state.Votes(ctx, p1.ID)
				require.NoError(err, "Votes()")
				require.Len(votes, 1, "one vote should exist")
				require.EqualValues(governance.VoteYes, votes[0].Vote, "vote should match submitted vote")
				require.EqualValues(addresses[1], votes[0].Voter, "vote should match submitted vote")
			},
		},
		{
			"vote override should work",
			signers[1].Public(),
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteNo,
			},
			nil,
			func() {
				// Ensure vote was overridden.
				var votes []*governance.VoteEntry
				votes, err = state.Votes(ctx, p1.ID)
				require.NoError(err, "Votes()")
				require.Len(votes, 1, "one vote should exist")
				require.EqualValues(governance.VoteNo, votes[0].Vote, "vote should match submitted vote")
				require.EqualValues(addresses[1], votes[0].Voter, "vote should match submitted vote")
			},
		},
		{
			"should work again",
			signers[2].Public(),
			&governance.ProposalVote{
				ID:   p1.ID,
				Vote: governance.VoteAbstain,
			},
			nil,
			func() {
				// Ensure vote exists.
				var votes []*governance.VoteEntry
				votes, err = state.Votes(ctx, p1.ID)
				require.NoError(err, "Votes()")
				require.Len(votes, 2, "two votes should exist")
				for _, v := range votes {
					if v.Vote != governance.VoteAbstain {
						continue
					}
					require.EqualValues(governance.VoteAbstain, v.Vote, "vote should match submitted vote")
					require.EqualValues(addresses[2], v.Voter, "vote should match submitted vote")
					return
				}
				t.Fatal("expected vote not found")
			},
		},
	} {
		txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
		defer txCtx.Close()
		txCtx.SetTxSigner(tc.txSigner)

		err = app.castVote(txCtx, state, tc.vote)
		require.Equal(tc.err, err, tc.msg)

		tc.check()
	}
}
