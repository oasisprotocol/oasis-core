package governance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	numValidators = 4
	numDelegators = 2
)

var testAccountsStake = quantity.NewFromUint64(100)

func initValidatorsEscrowState(
	t *testing.T,
	stakingState *stakingState.MutableState,
	registryState *registryState.MutableState,
	schedulerState *schedulerState.MutableState,
) ([]signature.Signer, []staking.Address, map[staking.Address]*staking.SharePool) {
	require := require.New(t)
	var err error
	ctx := context.Background()

	expectedValidatorsEscrow := make(map[staking.Address]*staking.SharePool)
	addresses := []staking.Address{}
	signers := []signature.Signer{}

	// Prepare some entities and nodes.
	validatorSet := make(map[signature.PublicKey]*scheduler.Validator)
	for i := 0; i < numValidators+numDelegators+1; i++ {
		nodeSigner := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance: node signer: %d", i))
		entitySigner := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance: entity signer: %d", i))
		signers = append(signers, entitySigner)

		ent := entity.Entity{
			Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
			ID:        entitySigner.Public(),
			Nodes:     []signature.PublicKey{nodeSigner.Public()},
		}
		sigEnt, entErr := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, &ent)
		require.NoError(entErr, "SignEntity")
		err = registryState.SetEntity(ctx, &ent, sigEnt)
		require.NoError(err, "SetEntity")
		addr := staking.NewAddress(entitySigner.Public())
		addresses = append(addresses, addr)

		nod := &node.Node{
			Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:        nodeSigner.Public(),
			Consensus: node.ConsensusInfo{ID: nodeSigner.Public()},
			EntityID:  entitySigner.Public(),
		}
		sigNode, nErr := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, nod)
		require.NoError(nErr, "MultiSignNode")
		err = registryState.SetNode(ctx, nil, nod, sigNode)
		require.NoError(err, "SetNode")

		switch {
		case i < numValidators:
			// First `numValidator` nodes are validators.
			validatorSet[nod.Consensus.ID] = &scheduler.Validator{
				ID:          nodeSigner.Public(),
				EntityID:    nod.EntityID,
				VotingPower: 1,
			}

			// Setup entity escrow.
			// Configure a balance.
			sp := staking.SharePool{
				TotalShares: *quantity.NewFromUint64(100),
				Balance:     *testAccountsStake,
			}
			err = stakingState.SetAccount(ctx, addr, &staking.Account{
				Escrow: staking.EscrowAccount{
					Active: sp,
				},
			})
			require.NoError(err, "SetAccount")
			expectedValidatorsEscrow[addr] = &sp

			require.NoError(stakingState.SetDelegation(ctx, addr, addr, &staking.Delegation{
				Shares: *quantity.NewFromUint64(100),
			}), "SetDelegation")
		case i == numValidators+numDelegators:
			// Last node has no delegations.
		default:
			// i > numValidator && i < numValidator+numDelegator are delegators to the first validator.

			// Delegate to first validator.
			acc, aerr := stakingState.Account(ctx, addresses[0])
			require.NoError(aerr, "Account")
			require.NoError(acc.Escrow.Active.TotalShares.Add(quantity.NewFromUint64(100)))
			expectedValidatorsEscrow[addresses[0]] = &acc.Escrow.Active
			require.NoError(stakingState.SetAccount(ctx, addresses[0], acc), "SetAccount")

			require.NoError(stakingState.SetDelegation(ctx, addr, addresses[0], &staking.Delegation{
				Shares: *quantity.NewFromUint64(100),
			}), "SetDelegation")
		}

		// Register two nodes for last validator (shouldn't affect expected validator entities escrow).
		if i == numValidators-1 {
			nodeSigner2 := memorySigner.NewTestSigner(fmt.Sprintf("consensus/tendermint/apps/governance: node signer2: %d", i))
			node2 := &node.Node{
				Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
				ID:        nodeSigner2.Public(),
				Consensus: node.ConsensusInfo{ID: nodeSigner2.Public()},
				EntityID:  entitySigner.Public(),
			}
			sigNode2, nErr2 := node.MultiSignNode([]signature.Signer{nodeSigner2}, registry.RegisterEntitySignatureContext, node2)
			require.NoError(nErr2, "MultiSignNode")
			err = registryState.SetNode(ctx, nil, node2, sigNode2)
			require.NoError(err, "SetNode")
			validatorSet[node2.Consensus.ID] = &scheduler.Validator{
				ID:          nodeSigner2.Public(),
				EntityID:    node2.EntityID,
				VotingPower: 1,
			}
		}
	}
	err = schedulerState.PutCurrentValidators(ctx, validatorSet)
	require.NoError(err, "PutCurrentValidators")

	return signers, addresses, expectedValidatorsEscrow
}

func TestValidatorsEscrow(t *testing.T) {
	require := require.New(t)
	var err error

	expectedTotalStake := testAccountsStake.Clone()
	err = expectedTotalStake.Mul(quantity.NewFromUint64(uint64(numValidators)))
	require.NoError(err, "Mul")

	// Setup state.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	registryState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())
	schedulerState := schedulerState.NewMutableState(ctx.State())
	_, _, expectedValidatorsEscrow := initValidatorsEscrowState(t, stakeState, registryState, schedulerState)

	// Test validatorsEscrow.
	totalStake, validatorsEscrow, err := validatorsEscrow(ctx, stakeState.ImmutableState, schedulerState.ImmutableState)
	require.NoError(err, "app.validatorsEscrow()")
	require.EqualValues(expectedTotalStake, totalStake, "total stake should match expected")
	require.EqualValues(expectedValidatorsEscrow, validatorsEscrow, "validators escrow should match expected")
}

func TestCloseProposal(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup staking state.
	stakingState := stakingState.NewMutableState(ctx.State())
	pk1 := signature.NewPublicKey("aaafffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr1 := staking.NewAddress(pk1)
	pk2 := signature.NewPublicKey("bbbfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr2 := staking.NewAddress(pk2)
	pk3 := signature.NewPublicKey("cccfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr3 := staking.NewAddress(pk3)
	pk4 := signature.NewPublicKey("dddfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr4 := staking.NewAddress(pk4)
	pk5 := signature.NewPublicKey("eeefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr5 := staking.NewAddress(pk5)
	pk6 := signature.NewPublicKey("aabfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr6 := staking.NewAddress(pk6)
	pk7 := signature.NewPublicKey("aacfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addr7 := staking.NewAddress(pk7)

	// Delegations setup.
	// Validators.
	require.NoError(stakingState.SetDelegation(ctx, addr1, addr1, &staking.Delegation{Shares: *quantity.NewFromUint64(4)}))
	require.NoError(stakingState.SetDelegation(ctx, addr1, addr3, &staking.Delegation{Shares: *quantity.NewFromUint64(12)}))
	require.NoError(stakingState.SetDelegation(ctx, addr2, addr2, &staking.Delegation{Shares: *quantity.NewFromUint64(60)}))
	require.NoError(stakingState.SetDelegation(ctx, addr3, addr3, &staking.Delegation{Shares: *quantity.NewFromUint64(35)}))
	require.NoError(stakingState.SetDelegation(ctx, addr3, addr1, &staking.Delegation{Shares: *quantity.NewFromUint64(50)}))
	// Delegators.
	require.NoError(stakingState.SetDelegation(ctx, addr4, addr4, &staking.Delegation{Shares: *quantity.NewFromUint64(5)}))
	require.NoError(stakingState.SetDelegation(ctx, addr5, addr1, &staking.Delegation{Shares: *quantity.NewFromUint64(6)}))
	require.NoError(stakingState.SetDelegation(ctx, addr6, addr6, &staking.Delegation{Shares: *quantity.NewFromUint64(100)}))
	require.NoError(stakingState.SetDelegation(ctx, addr6, addr7, &staking.Delegation{Shares: *quantity.NewFromUint64(200)}))
	require.NoError(stakingState.SetDelegation(ctx, addr6, addr1, &staking.Delegation{Shares: *quantity.NewFromUint64(1)}))
	require.NoError(stakingState.SetDelegation(ctx, addr7, addr7, &staking.Delegation{Shares: *quantity.NewFromUint64(10)}))

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

	baseValidatorEntitiesEscrow := map[staking.Address]*staking.SharePool{
		addr1: {
			Balance: *quantity.NewFromUint64(100),
			// Shares:
			// - addr1: 4
			// - addr3: 50
			// - addr5: 6
			// - addr6: 1
			TotalShares: *quantity.NewFromUint64(61),
		},
		addr2: {
			Balance: *quantity.NewFromUint64(60),
			// Shares:
			// - addr2: 60
			TotalShares: *quantity.NewFromUint64(60),
		},
		addr3: {
			Balance: *quantity.NewFromUint64(35),
			// Shares:
			// - addr1: 12
			// - addr3: 35
			TotalShares: *quantity.NewFromUint64(47),
		},
	}

	for _, tc := range []struct {
		msg                     string
		params                  *governance.ConsensusParameters
		totalVotingStake        *quantity.Quantity
		validatorEntitiesEscrow map[staking.Address]*staking.SharePool
		proposal                *governance.Proposal
		votes                   []*governance.VoteEntry
		expectedState           governance.ProposalState
		expectedInvalidVotes    uint64
		expectedResults         map[governance.Vote]quantity.Quantity
	}{
		{
			"should be rejected with no votes",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    1,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{},
			governance.StateRejected,
			0,
			make(map[governance.Vote]quantity.Quantity),
		},
		{
			"should be rejected with majority no votes",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    2,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteNo},
				{Voter: addr2, Vote: governance.VoteNo},
				{Voter: addr3, Vote: governance.VoteNo},
				{Voter: addr4, Vote: governance.VoteNo},
			},
			governance.StateRejected,
			1, // addr4 - is invalid vote as it's not part of the 'baseValidatorEntitiesEscrow'.
			map[governance.Vote]quantity.Quantity{
				governance.VoteNo: *quantity.NewFromUint64(195),
			},
		},
		{
			"should be rejected if quorum not reached",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    3,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteYes},
			},
			governance.StateRejected,
			0,
			map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(100 + 8), // 100 + 8 (shares in addr3).
			},
		},
		{
			"should be rejected if threshold not reached",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    4,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteYes},
				{Voter: addr2, Vote: governance.VoteNo},
				{Voter: addr3, Vote: governance.VoteYes},
			},
			governance.StateRejected,
			0,
			map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(100 + 35), // 100% of addr1 shares + 100% addr3 shares.
				governance.VoteNo:  *quantity.NewFromUint64(60),
			},
		},
		{
			"should be rejected if threshold not reached (validator + delegator)",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    5,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteYes},
				{Voter: addr3, Vote: governance.VoteNo},
			},
			governance.StateRejected,
			0,
			map[governance.Vote]quantity.Quantity{
				governance.VoteYes: *quantity.NewFromUint64(18 + 8),  // 11 shares of addr1 + 12 shares of addr3.
				governance.VoteNo:  *quantity.NewFromUint64(26 + 81), // 35 shares of addr3 + 50 shares of addr1.
			},
		},
		{
			"should pass",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    6,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteNo},
				{Voter: addr2, Vote: governance.VoteYes},
				{Voter: addr3, Vote: governance.VoteYes},
				{Voter: addr5, Vote: governance.VoteYes},
			},
			governance.StatePassed,
			0,
			map[governance.Vote]quantity.Quantity{
				governance.VoteNo:  *quantity.NewFromUint64(8 + 8),        // 5 shares of addr1 + 12 shares of addr3.
				governance.VoteYes: *quantity.NewFromUint64(60 + 26 + 91), // 60 shares of addr2 + 35 shares of addr3 + 56 shares of addr1.
			},
		},
		{
			"delegator override should work",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    7,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr1, Vote: governance.VoteNo},
				{Voter: addr2, Vote: governance.VoteYes},
				{Voter: addr3, Vote: governance.VoteYes},
				{Voter: addr4, Vote: governance.VoteNo},
				{Voter: addr5, Vote: governance.VoteYes},
				{Voter: addr6, Vote: governance.VoteAbstain},
			},
			governance.StatePassed,
			1,
			map[governance.Vote]quantity.Quantity{
				governance.VoteYes:     *quantity.NewFromUint64(60 + 26 + 91), // 60 shares of addr2 + 35 shares of addr3 + 56 shares of addr1.
				governance.VoteNo:      *quantity.NewFromUint64(6 + 8),        // 4 shares of addr1 + 12 shares of addr3.
				governance.VoteAbstain: *quantity.NewFromUint64(1),            // 1 share of addr1.
			},
		},
		{
			"delegator override should work if validator doesn't vote",
			baseConsParams,
			quantity.NewFromUint64(195),
			baseValidatorEntitiesEscrow,
			&governance.Proposal{
				ID:    8,
				State: governance.StateActive,
			},
			[]*governance.VoteEntry{
				{Voter: addr2, Vote: governance.VoteYes},
				{Voter: addr3, Vote: governance.VoteYes},
				{Voter: addr4, Vote: governance.VoteNo},
				{Voter: addr5, Vote: governance.VoteYes},
				{Voter: addr6, Vote: governance.VoteAbstain},
			},
			governance.StatePassed,
			1,
			map[governance.Vote]quantity.Quantity{
				governance.VoteYes:     *quantity.NewFromUint64(60 + 35 + 91), // 60 shares of addr2 + 47 shares of addr3 + 56 shares of addr1.
				governance.VoteAbstain: *quantity.NewFromUint64(1),            // 1 share of addr1.
			},
		},
	} {
		err = state.SetConsensusParameters(ctx, tc.params)
		require.NoError(err, "setting governance consensus parameters should not error")

		for _, vote := range tc.votes {
			err = state.SetVote(ctx, tc.proposal.ID, vote.Voter, vote.Vote)
			require.NoError(err, "SetVote()")
		}

		err = app.closeProposal(ctx, state, stakingState.ImmutableState, *tc.totalVotingStake, tc.validatorEntitiesEscrow, tc.proposal)
		require.NoError(err, tc.msg)

		require.EqualValues(tc.expectedState, tc.proposal.State, tc.msg)
		require.EqualValues(tc.expectedInvalidVotes, tc.proposal.InvalidVotes, tc.msg)
		require.EqualValues(tc.expectedResults, tc.proposal.Results, tc.msg)
	}
}

func TestExecuteProposal(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	defaultUpgradeProposal := governance.UpgradeProposal{
		Descriptor: upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Handler:   "default",
			Target:    version.Versions,
			Epoch:     20,
		},
	}
	defaultAtEpoch := func(epoch beacon.EpochTime) *governance.UpgradeProposal {
		proposal := defaultUpgradeProposal
		proposal.Descriptor.Epoch = epoch
		return &proposal
	}

	// Setup governance state.
	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}
	// Consensus parameters.
	err = state.SetConsensusParameters(ctx, &governance.ConsensusParameters{
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		StakeThreshold:            90,
		UpgradeMinEpochDiff:       10,
		UpgradeCancelMinEpochDiff: 10,
	})
	require.NoError(err, "setting governance consensus parameters should not error")
	// Prepare proposals.
	err = state.SetProposal(ctx,
		&governance.Proposal{ID: 1, Content: governance.ProposalContent{Upgrade: &defaultUpgradeProposal}},
	)
	require.NoError(err, "SetProposal")
	err = state.SetProposal(ctx, &governance.Proposal{ID: 2, Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 1}}})
	require.NoError(err, "SetProposal")
	err = state.SetProposal(ctx, &governance.Proposal{ID: 3, Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 1}}})
	require.NoError(err, "SetProposal")
	err = state.SetPendingUpgrade(ctx, 1, &defaultUpgradeProposal.Descriptor)
	require.NoError(err, "SetPendingUpgrade")

	for _, tc := range []struct {
		msg      string
		proposal *governance.Proposal
		err      error
	}{
		{
			"executing upgrade proposal should fail if upgrade is already pending",
			&governance.Proposal{
				ID:      4,
				Content: governance.ProposalContent{Upgrade: &defaultUpgradeProposal},
			},
			governance.ErrUpgradeAlreadyPending,
		},
		{
			"executing cancel upgrade should fail for nonexisting proposal",
			&governance.Proposal{
				ID:      5,
				Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 6}},
			},
			governance.ErrNoSuchProposal,
		},
		{
			"executing cancel upgrade should fail for nonexisting pending upgrade",
			&governance.Proposal{
				ID:      6,
				Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 3}},
			},
			governance.ErrNoSuchUpgrade,
		},
		{
			"executing cancel upgrade should fail for cancel upgrade proposal",
			&governance.Proposal{
				ID:      6,
				Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 2}},
			},
			governance.ErrNoSuchUpgrade,
		},
		{
			"executing cancel upgrade should work",
			&governance.Proposal{
				ID:      6,
				Content: governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 1}},
			},
			nil,
		},
		{
			"executing upgrade proposal should now work",
			&governance.Proposal{
				ID:      7,
				Content: governance.ProposalContent{Upgrade: &defaultUpgradeProposal},
			},
			nil,
		},
		{
			"executing upgrade proposal should again fail with existing upgrade for same epoch",
			&governance.Proposal{
				ID:      8,
				Content: governance.ProposalContent{Upgrade: &defaultUpgradeProposal},
			},
			governance.ErrUpgradeAlreadyPending,
		},
		{
			"executing upgrade proposal should fail with existing upgrade just before the upgrade epoch",
			&governance.Proposal{
				ID: 9,
				Content: governance.ProposalContent{
					// Already scheduled upgrade is at epoch 20.
					Upgrade: defaultAtEpoch(22),
				},
			},
			governance.ErrUpgradeAlreadyPending,
		},
		{
			"executing upgrade proposal should fail with existing upgrade just after the upgrade epoch",
			&governance.Proposal{
				ID: 10,
				Content: governance.ProposalContent{
					// Already scheduled upgrade is at epoch 20.
					Upgrade: defaultAtEpoch(18),
				},
			},
			governance.ErrUpgradeAlreadyPending,
		},
		{
			"executing upgrade proposal work with existing upgrade far enough from the upgrade epoch",
			&governance.Proposal{
				ID: 11,
				Content: governance.ProposalContent{
					// Already scheduled upgrade is at epoch 20.
					Upgrade: defaultAtEpoch(32),
				},
			},
			nil,
		},
		{
			"executing upgrade proposal work with existing upgrade far enough from the upgrade epoch",
			&governance.Proposal{
				ID: 12,
				Content: governance.ProposalContent{
					// Already scheduled upgrade is at epoch 20.
					Upgrade: defaultAtEpoch(8),
				},
			},
			nil,
		},
	} {
		err = app.executeProposal(ctx, state, tc.proposal)
		if tc.err != nil {
			// Expected proposal to fail.
			require.Equal(governance.StateFailed, tc.proposal.State, tc.msg)
			require.True(errors.Is(err, tc.err),
				fmt.Sprintf("expected error: %v, got: %v, for: %s", tc.err, err, tc.msg))

			continue
		}
		// Expected proposal to pass.
		require.NoError(err, tc.msg)
		require.Equal(governance.StatePassed, tc.proposal.State, tc.msg)

		// Save the updated proposal.
		err = state.SetProposal(ctx, tc.proposal)
		require.NoError(err, "SetProposal")
	}
}

func TestBeginBlock(t *testing.T) {
	require := require.New(t)
	var err error

	// Prepare state.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()
	state := governanceState.NewMutableState(ctx.State())

	app := &governanceApplication{
		state: appState,
	}

	// Prepare some pending upgrades.
	upgrade11 := &governance.UpgradeProposal{
		Descriptor: upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Target:    version.Versions,
			Epoch:     11,
		},
	}
	upgrade12 := &governance.UpgradeProposal{
		Descriptor: upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Target:    version.Versions,
			Epoch:     12,
		},
	}
	err = state.SetProposal(ctx, &governance.Proposal{ID: 1, Content: governance.ProposalContent{Upgrade: upgrade11}})
	require.NoError(err, "SetProposal")
	err = state.SetProposal(ctx, &governance.Proposal{ID: 2, Content: governance.ProposalContent{Upgrade: upgrade12}})
	require.NoError(err, "SetProposal")
	err = state.SetPendingUpgrade(ctx, 1, &upgrade11.Descriptor)
	require.NoError(err, "SetPendingUpgrade")
	err = state.SetPendingUpgrade(ctx, 2, &upgrade12.Descriptor)
	require.NoError(err, "SetPendingUpgrade")

	for _, tc := range []struct {
		msg            string
		epoch          beacon.EpochTime
		isEpochChanged bool
		check          func(ctx *abciAPI.Context, state *governanceState.MutableState)
	}{
		{
			"nothing to do if no upgrades for current epoch change",
			beacon.EpochTime(10),
			true,
			func(ctx *abciAPI.Context, state *governanceState.MutableState) {
				var upgrades []*upgrade.Descriptor
				upgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(upgrades, 2, "all pending upgrades should remain")
			},
		},
		{
			"nothing to do if epoch not changed",
			beacon.EpochTime(11),
			false,
			func(ctx *abciAPI.Context, state *governanceState.MutableState) {
				var upgrades []*upgrade.Descriptor
				upgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(upgrades, 2, "all pending upgrades should remain")
			},
		},
		{
			"upgrade should be executed on epoch 11",
			beacon.EpochTime(11),
			true,
			func(ctx *abciAPI.Context, state *governanceState.MutableState) {
				var upgrades []*upgrade.Descriptor
				upgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(upgrades, 1, "one pending upgrade should remain")
				require.EqualValues(upgrades[0].Epoch, beacon.EpochTime(12), "upgrade for epoch12 should remain")
			},
		},
		{
			"upgrade should be executed on epoch 12",
			beacon.EpochTime(12),
			true,
			func(ctx *abciAPI.Context, state *governanceState.MutableState) {
				var upgrades []*upgrade.Descriptor
				upgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(upgrades, 0, "no upgrades should remain")
			},
		},
		{
			"nothing to do on epoch 13",
			beacon.EpochTime(13),
			true,
			func(ctx *abciAPI.Context, state *governanceState.MutableState) {
				var upgrades []*upgrade.Descriptor
				upgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(upgrades, 0, "no upgrades should remain")
			},
		},
	} {
		appState.UpdateMockApplicationStateConfig(&abciAPI.MockApplicationStateConfig{
			CurrentEpoch: tc.epoch,
			EpochChanged: tc.isEpochChanged,
		})

		err = app.BeginBlock(ctx, types.RequestBeginBlock{})
		require.NoError(err, tc.msg)

		tc.check(ctx, state)
	}
}

func TestEndBlock(t *testing.T) {
	require := require.New(t)
	var err error

	// Prepare state.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()
	state := governanceState.NewMutableState(ctx.State())

	app := &governanceApplication{
		state: appState,
	}

	registryState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())
	schedulerState := schedulerState.NewMutableState(ctx.State())
	_, accounts, expectedValidatorsEscrow := initValidatorsEscrowState(t, stakeState, registryState, schedulerState)

	commonPoolBalance := quantity.NewFromUint64(1000)
	governanceDepositsBalance := quantity.NewFromUint64(500)

	err = stakeState.SetCommonPool(ctx, commonPoolBalance)
	require.NoError(err, "SetCommonPool")
	err = stakeState.SetGovernanceDeposits(ctx, governanceDepositsBalance)
	require.NoError(err, "SetGovernanceDeposits")

	// Prepare some proposals.
	setupActiveProposal := func(p *governance.Proposal, shouldPass bool) {
		err = state.SetActiveProposal(ctx, p)
		require.NoError(err, "SetActiveProposal")
		for valAddr := range expectedValidatorsEscrow {
			switch shouldPass {
			case true:
				err = state.SetVote(ctx, p.ID, valAddr, governance.VoteYes)
				require.NoError(err, "Vote")
			case false:
				err = state.SetVote(ctx, p.ID, valAddr, governance.VoteNo)
				require.NoError(err, "Vote")
			}
		}
	}

	// Upgrade proposal that should be rejected at epoch 11.
	upgrade11 := &governance.UpgradeProposal{
		Descriptor: baseAtEpoch(11),
	}
	p1 := &governance.Proposal{
		ID:        1,
		Submitter: accounts[0],
		Deposit:   *quantity.NewFromUint64(100),
		Content:   governance.ProposalContent{Upgrade: upgrade11},
		ClosesAt:  11,
		State:     governance.StateActive,
	}
	setupActiveProposal(p1, false)

	// Upgrade proposal that should pass at epoch 12.
	upgrade12 := &governance.UpgradeProposal{
		Descriptor: baseAtEpoch(30),
	}
	p2 := &governance.Proposal{
		ID:        2,
		Submitter: accounts[1],
		Deposit:   *quantity.NewFromUint64(100),
		Content:   governance.ProposalContent{Upgrade: upgrade12},
		ClosesAt:  12,
		State:     governance.StateActive,
	}
	setupActiveProposal(p2, true)

	// Cancel proposal that should pass (but fail) at epoch 13.
	p3 := &governance.Proposal{
		ID:        3,
		Submitter: accounts[2],
		Deposit:   *quantity.NewFromUint64(100),
		Content:   governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 1}},
		ClosesAt:  13,
		State:     governance.StateActive,
	}
	setupActiveProposal(p3, true)

	// Cancel proposal that should pass at epoch 14.
	p4 := &governance.Proposal{
		ID:        4,
		Submitter: accounts[3],
		Deposit:   *quantity.NewFromUint64(100),
		Content:   governance.ProposalContent{CancelUpgrade: &governance.CancelUpgradeProposal{ProposalID: 2}},
		ClosesAt:  14,
		State:     governance.StateActive,
	}
	setupActiveProposal(p4, true)

	err = state.SetConsensusParameters(ctx, &governance.ConsensusParameters{
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		StakeThreshold:            90,
		UpgradeMinEpochDiff:       10,
		UpgradeCancelMinEpochDiff: 10,
	})
	require.NoError(err, "setting governance consensus parameters should not error")

	for _, tc := range []struct {
		msg            string
		epoch          beacon.EpochTime
		isEpochChanged bool
		check          func()
	}{
		{
			"nothing to do if no active proposals closing on this epoch",
			beacon.EpochTime(10),
			true,
			func() {
				var proposals []*governance.Proposal
				proposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(proposals, 4, "all active proposals should remain")
			},
		},
		{
			"nothing to do if no not epoch changed",
			beacon.EpochTime(11),
			false,
			func() {
				var proposals []*governance.Proposal
				proposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "PendingUpgrades")
				require.Len(proposals, 4, "all active proposals should remain")
			},
		},
		{
			"upgrade proposal should be rejected",
			beacon.EpochTime(11),
			true,
			func() {
				var activeProposals []*governance.Proposal
				activeProposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "ActiveProposals")
				require.Len(activeProposals, 3, "3 active proposal should remain")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals()")
				require.Len(proposals, 4, "all proposals should remain")
				require.EqualValues(proposals[0].State, governance.StateRejected, "proposal should be rejected")

				// There should be no pending upgrades.
				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades()")
				require.Len(pendingUpgrades, 0, "no upgrades should be pending")

				// Proposal deposit should be discarded into the common pool.
				var acc *staking.Account
				acc, err = stakeState.Account(ctx, proposals[0].Submitter)
				require.NoError(err, "Account")
				require.EqualValues(*quantity.NewQuantity(), acc.General.Balance, "rejected proposal should not reclaim deposit")

				err = commonPoolBalance.Add(&proposals[0].Deposit)
				require.NoError(err, "Add")
				err = governanceDepositsBalance.Sub(&proposals[0].Deposit)
				require.NoError(err, "Sub")

				var commonPool *quantity.Quantity
				commonPool, err = stakeState.CommonPool(ctx)
				require.NoError(err, "CommonPool")

				var govDep *quantity.Quantity
				govDep, err = stakeState.GovernanceDeposits(ctx)
				require.NoError(err, "GovernanceDeposits")

				require.EqualValues(commonPoolBalance, commonPool, "common pool balance should be expected")
				require.EqualValues(governanceDepositsBalance, govDep, "governance deposits balance should be expected")
			},
		},
		{
			"upgrade proposal should pass",
			beacon.EpochTime(12),
			true,
			func() {
				var activeProposals []*governance.Proposal
				activeProposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "ActiveProposals")
				require.Len(activeProposals, 2, "2 active proposal should remain")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals()")
				require.Len(proposals, 4, "all proposals should remain")
				require.EqualValues(proposals[1].State, governance.StatePassed, "proposal should pass")

				// Pending upgrade should be created.
				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades()")
				require.Len(pendingUpgrades, 1, "One upgrade should be pending")

				// Proposal deposit should be reclaimed to the submitter.
				var acc *staking.Account
				acc, err = stakeState.Account(ctx, proposals[1].Submitter)
				require.NoError(err, "Account")
				require.EqualValues(proposals[1].Deposit, acc.General.Balance, "rejected proposal should not reclaim deposit")

				err = governanceDepositsBalance.Sub(&proposals[1].Deposit)
				require.NoError(err, "Sub")

				var commonPool *quantity.Quantity
				commonPool, err = stakeState.CommonPool(ctx)
				require.NoError(err, "CommonPool")

				var govDep *quantity.Quantity
				govDep, err = stakeState.GovernanceDeposits(ctx)
				require.NoError(err, "GovernanceDeposits")

				require.EqualValues(commonPoolBalance, commonPool, "common pool balance should be expected")
				require.EqualValues(governanceDepositsBalance, govDep, "governance deposits balance should be expected")
			},
		},
		{
			"cancel upgrade proposal should pass but fail",
			beacon.EpochTime(13),
			true,
			func() {
				var activeProposals []*governance.Proposal
				activeProposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "ActiveProposals")
				require.Len(activeProposals, 1, "1 active proposal should remain")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals()")
				require.Len(proposals, 4, "all proposals should remain")
				require.EqualValues(proposals[2].State, governance.StateFailed, "proposal should fail")

				// Pending upgrade should remain.
				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades()")
				require.Len(pendingUpgrades, 1, "One upgrade should be pending")

				// Proposal deposit should be reclaimed to the submitter.
				var acc *staking.Account
				acc, err = stakeState.Account(ctx, proposals[2].Submitter)
				require.NoError(err, "Account")
				require.EqualValues(proposals[1].Deposit, acc.General.Balance, "rejected proposal should not reclaim deposit")

				err = governanceDepositsBalance.Sub(&proposals[2].Deposit)
				require.NoError(err, "Sub")

				var commonPool *quantity.Quantity
				commonPool, err = stakeState.CommonPool(ctx)
				require.NoError(err, "CommonPool")

				var govDep *quantity.Quantity
				govDep, err = stakeState.GovernanceDeposits(ctx)
				require.NoError(err, "GovernanceDeposits")

				require.EqualValues(commonPoolBalance, commonPool, "common pool balance should be expected")
				require.EqualValues(governanceDepositsBalance, govDep, "governance deposits balance should be expected")
			},
		},
		{
			"cancel upgrade proposal should pass and succeed",
			beacon.EpochTime(14),
			true,
			func() {
				var activeProposals []*governance.Proposal
				activeProposals, err = state.ActiveProposals(ctx)
				require.NoError(err, "ActiveProposals")
				require.Len(activeProposals, 0, "0 active proposal should remain")

				var proposals []*governance.Proposal
				proposals, err = state.Proposals(ctx)
				require.NoError(err, "Proposals()")
				require.Len(proposals, 4, "all proposals should remain")
				require.EqualValues(proposals[3].State, governance.StatePassed, "proposal should pass")

				// Pending upgrade should be removed.
				var pendingUpgrades []*upgrade.Descriptor
				pendingUpgrades, err = state.PendingUpgrades(ctx)
				require.NoError(err, "PendingUpgrades()")
				require.Len(pendingUpgrades, 0, "no upgrade should be pending")

				// Proposal deposit should be reclaimed to the submitter.
				var acc *staking.Account
				acc, err = stakeState.Account(ctx, proposals[3].Submitter)
				require.NoError(err, "Account")
				require.EqualValues(proposals[1].Deposit, acc.General.Balance, "rejected proposal should not reclaim deposit")

				err = governanceDepositsBalance.Sub(&proposals[3].Deposit)
				require.NoError(err, "Sub")

				var commonPool *quantity.Quantity
				commonPool, err = stakeState.CommonPool(ctx)
				require.NoError(err, "CommonPool")

				var govDep *quantity.Quantity
				govDep, err = stakeState.GovernanceDeposits(ctx)
				require.NoError(err, "GovernanceDeposits")

				require.EqualValues(commonPoolBalance, commonPool, "common pool balance should be expected")
				require.EqualValues(governanceDepositsBalance, govDep, "governance deposits balance should be expected")
			},
		},
	} {
		appState.UpdateMockApplicationStateConfig(&abciAPI.MockApplicationStateConfig{
			CurrentEpoch: tc.epoch,
			EpochChanged: tc.isEpochChanged,
		})

		_, err = app.EndBlock(ctx, types.RequestEndBlock{})
		require.NoError(err, tc.msg)

		tc.check()
	}
}
