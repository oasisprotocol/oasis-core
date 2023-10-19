package e2e

import (
	"context"
	"fmt"
	"reflect"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var rewardScheduleChanges = staking.ConsensusParameterChanges{
	RewardSchedule: &[]staking.RewardStep{
		// 1% until the end of time.
		{
			Until: beacon.EpochMax,
			Scale: *quantity.NewFromUint64(1_000_000),
		},
	},
}

// ChangeParametersRewardSchedule is the governance change parameters scenario
// that changes the reward schedule.
var ChangeParametersRewardSchedule scenario.Scenario = newChangeRewardScheduleImpl(
	"change-parameters-reward-schedule",
	&api.ChangeParametersProposal{
		Module:  staking.ModuleName,
		Changes: cbor.Marshal(rewardScheduleChanges),
	},
)

type changeRewardScheduleImpl struct {
	Scenario

	ctx        context.Context
	parameters *api.ChangeParametersProposal

	currentEpoch beacon.EpochTime
	entityNonce  uint64
	entity       *oasis.Entity
}

func newChangeRewardScheduleImpl(name string, parameters *api.ChangeParametersProposal) scenario.Scenario {
	sc := &changeRewardScheduleImpl{
		Scenario:   *NewScenario(name),
		parameters: parameters,
	}
	return sc
}

func (sc *changeRewardScheduleImpl) Clone() scenario.Scenario {
	return &changeRewardScheduleImpl{
		Scenario:     *sc.Scenario.Clone().(*Scenario),
		parameters:   sc.parameters,
		currentEpoch: sc.currentEpoch,
		entityNonce:  sc.entityNonce,
	}
}

func (sc *changeRewardScheduleImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Needed so we can fast-forward to upgrade epoch.
	f.Network.SetMockEpoch()
	// Needed as we will vote as validators.
	f.Network.DeterministicIdentities = true

	f.Network.GovernanceParameters = &api.ConsensusParameters{
		MinProposalDeposit:        *quantity.NewFromUint64(100),
		VotingPeriod:              5,
		StakeThreshold:            100,
		UpgradeMinEpochDiff:       20,
		UpgradeCancelMinEpochDiff: 8,
	}
	f.Network.StakingGenesis = &staking.Genesis{
		TotalSupply: *quantity.NewFromUint64(1_201_000_000),
		CommonPool:  *quantity.NewFromUint64(1_000_000_000),
		Parameters: staking.ConsensusParameters{
			CommissionScheduleRules: staking.CommissionScheduleRules{
				RateChangeInterval: 1,
				RateBoundLead:      1,
				MaxRateSteps:       1,
				MaxBoundSteps:      1,
			},
			// Initial reward schedule (we'll change this with a proposal during
			// the course of this e2e test).
			RewardSchedule: []staking.RewardStep{
				// Reward 10% for the first 20 epochs.
				{
					Until: 20,
					Scale: *quantity.NewFromUint64(10_000_000),
				},
			},
			// Give full rewards each epoch to entities that have signed over
			// at least a third of all blocks signed that epoch.
			RewardFactorEpochSigned:           *quantity.NewFromUint64(1),
			SigningRewardThresholdNumerator:   1,
			SigningRewardThresholdDenominator: 3,
		},
		Ledger: map[staking.Address]*staking.Account{
			// Fund entity account so we'll be able to submit the proposal.
			DeterministicEntity1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(1_000_000),
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100_000_000),
						TotalShares: *quantity.NewFromUint64(100_000_000),
					},
					// Note that the scale for the rates in the commission
					// schedule is 1/1_000 and not 1/1_000_000 as in the reward
					// schedule.
					CommissionSchedule: staking.CommissionSchedule{
						Rates: []staking.CommissionRateStep{
							{
								Start: 0,
								Rate:  *quantity.NewFromUint64(10_000), // 10%
							},
						},
						Bounds: []staking.CommissionRateBoundStep{
							{
								Start:   0,
								RateMin: *quantity.NewFromUint64(0),       // 0%
								RateMax: *quantity.NewFromUint64(100_000), // 100%
							},
						},
					},
				},
			},
			DeterministicValidator0: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100_000_000),
						TotalShares: *quantity.NewFromUint64(100_000_000),
					},
					CommissionSchedule: staking.CommissionSchedule{
						Rates: []staking.CommissionRateStep{
							{
								Start: 0,
								Rate:  *quantity.NewFromUint64(10_000), // 10%
							},
						},
						Bounds: []staking.CommissionRateBoundStep{
							{
								Start:   0,
								RateMin: *quantity.NewFromUint64(0),       // 0%
								RateMax: *quantity.NewFromUint64(100_000), // 100%
							},
						},
					},
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			DeterministicEntity1: {
				DeterministicValidator0: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100_000_000),
				},
			},
			DeterministicValidator0: {
				DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100_000_000),
				},
			},
		},
	}

	return f, nil
}

func (sc *changeRewardScheduleImpl) nextEpoch() error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(sc.ctx, sc.currentEpoch); err != nil {
		// Errors can happen because an upgrade happens exactly during an epoch
		// transition.  So make sure to ignore them.
		sc.Logger.Warn("failed to set epoch",
			"epoch", sc.currentEpoch,
			"err", err,
		)
	}
	return nil
}

func (sc *changeRewardScheduleImpl) fetchAccount(owner staking.Address) (*staking.Account, error) {
	a, err := sc.Net.Controller().Staking.Account(sc.ctx,
		&staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  owner,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed querying account: %w", err)
	}

	return a, nil
}

func (sc *changeRewardScheduleImpl) fetchEscrowBalance(owner staking.Address) (*quantity.Quantity, error) {
	a, err := sc.fetchAccount(owner)
	if err != nil {
		return nil, err
	}
	return &a.Escrow.Active.Balance, nil
}

func (sc *changeRewardScheduleImpl) Run(ctx context.Context, _ *env.Env) error {
	sc.ctx = ctx

	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait for the validators to come up.
	sc.Logger.Info("waiting for validators to initialize",
		"num_validators", len(sc.Net.Validators()),
	)
	for _, n := range sc.Net.Validators() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}

	if err := sc.nextEpoch(); err != nil {
		return err
	}

	// Consensus parameters before the vote should be different from the ones
	// we want to have after the vote.
	oldParams, err := sc.Net.Controller().Staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(oldParams.RewardSchedule, *rewardScheduleChanges.RewardSchedule) {
		return fmt.Errorf("starting reward schedule is incorrect")
	}

	sc.entity = sc.Net.Entities()[1]
	entityAcc, err := sc.fetchAccount(DeterministicEntity1)
	if err != nil {
		return err
	}
	sc.entityNonce = entityAcc.General.Nonce

	acc := DeterministicEntity1

	initialBalance, err := sc.fetchEscrowBalance(acc)
	if err != nil {
		return err
	}
	sc.Logger.Info("initial escrow balance", "balance", initialBalance)

	// Do an epoch transition.
	sc.Logger.Info("first epoch transition")
	if err = sc.nextEpoch(); err != nil {
		return err
	}
	balance1, err := sc.fetchEscrowBalance(acc)
	if err != nil {
		return err
	}
	sc.Logger.Info("escrow balance after first epoch transition", "balance", balance1)

	if initialBalance.Cmp(balance1) != -1 {
		return fmt.Errorf("should have received a reward after first epoch transition")
	}

	// Do an epoch transition.
	sc.Logger.Info("second epoch transition")
	if err = sc.nextEpoch(); err != nil {
		return err
	}
	balance2, err := sc.fetchEscrowBalance(acc)
	if err != nil {
		return err
	}
	sc.Logger.Info("escrow balance after second epoch transition", "balance", balance2)

	if balance1.Cmp(balance2) != -1 {
		return fmt.Errorf("should have received a reward after second epoch transition")
	}

	// Submit change parameters proposal.
	content := &api.ProposalContent{
		ChangeParameters: sc.parameters,
	}
	_, sc.entityNonce, sc.currentEpoch, err = sc.EnsureProposalFinalized(ctx, content, sc.entity, sc.entityNonce, sc.currentEpoch)
	if err != nil {
		return fmt.Errorf("upgrade proposal error: %w", err)
	}

	// The consensus parameters after the proposal has been finalized
	// should match the parameters we proposed.
	newParams, err := sc.Net.Controller().Staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(newParams.RewardSchedule, *rewardScheduleChanges.RewardSchedule) {
		return fmt.Errorf("failed to change reward schedule")
	}

	// Do an epoch transition.
	sc.Logger.Info("third epoch transition")
	if err = sc.nextEpoch(); err != nil {
		return err
	}
	balance3, err := sc.fetchEscrowBalance(acc)
	if err != nil {
		return err
	}
	sc.Logger.Info("escrow balance after third epoch transition", "balance", balance3)

	// Do an epoch transition.
	sc.Logger.Info("fourth epoch transition")
	if err = sc.nextEpoch(); err != nil {
		return err
	}
	balance4, err := sc.fetchEscrowBalance(acc)
	if err != nil {
		return err
	}
	sc.Logger.Info("escrow balance after fourth epoch transition", "balance", balance4)

	if balance3.Cmp(balance4) != -1 {
		return fmt.Errorf("should have received a reward after fourth epoch transition")
	}

	// We should have received greater rewards between 2nd and 1st transition
	// than between 4th and 3rd, because the original reward schedule awarded
	// 10% and the new one only 1%.
	diff21 := balance2.Clone()
	if err = diff21.Sub(balance1); err != nil {
		return err
	}
	diff43 := balance4.Clone()
	if err = diff43.Sub(balance3); err != nil {
		return err
	}
	if diff43.Cmp(diff21) != -1 {
		return fmt.Errorf("rewards before the schedule change should have been greater than the rewards after the schedule change")
	}

	return nil
}
