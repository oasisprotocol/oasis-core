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

var (
	minCommissionRateChanges = staking.ConsensusParameterChanges{
		MinCommissionRate: quantity.NewFromUint64(40_000),
	}
	entity1CommissionSchedule = staking.CommissionSchedule{
		Rates: []staking.CommissionRateStep{
			{
				Start: 0,
				Rate:  *quantity.NewFromUint64(30_000),
			},
		},
		Bounds: []staking.CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: *quantity.NewFromUint64(10_000),
				RateMax: *quantity.NewFromUint64(100_000),
			},
			{
				Start:   200,
				RateMin: *quantity.NewFromUint64(20_000),
				RateMax: *quantity.NewFromUint64(90_000),
			},
		},
	}
	entity2CommissionSchedule = staking.CommissionSchedule{
		Rates: []staking.CommissionRateStep{
			{
				Start: 0,
				Rate:  *quantity.NewFromUint64(60_000),
			},
		},
		Bounds: []staking.CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: *quantity.NewFromUint64(0),
				RateMax: *quantity.NewFromUint64(100_000),
			},
		},
	}
	entity3CommissionSchedule = staking.CommissionSchedule{
		Rates: []staking.CommissionRateStep{
			{
				Start: 0,
				Rate:  *quantity.NewFromUint64(15_000),
			},
			{
				Start: 100,
				Rate:  *quantity.NewFromUint64(20_000),
			},
			{
				Start: 800,
				Rate:  *quantity.NewFromUint64(15_000),
			},
		},
		Bounds: []staking.CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: *quantity.NewFromUint64(20_00),
				RateMax: *quantity.NewFromUint64(100_000),
			},
			{
				Start:   500,
				RateMin: *quantity.NewFromUint64(10_00),
				RateMax: *quantity.NewFromUint64(20_000),
			},
		},
	}
)

type minCommissionRateChecker struct{}

func (n *minCommissionRateChecker) PreUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Ensure min commission rate is set to 0 before upgrade.
	params, err := ctrl.Staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	if !params.CommissionScheduleRules.MinCommissionRate.IsZero() {
		return fmt.Errorf("expected zero min commission rate before upgrade, got: %v", params.CommissionScheduleRules.MinCommissionRate)
	}
	// Ensure expected commission schedules exist.
	expectedSchedules := []staking.CommissionSchedule{entity1CommissionSchedule, entity2CommissionSchedule, entity3CommissionSchedule}
	for i, addr := range []staking.Address{DeterministicEntity1, DeterministicEntity2, DeterministicEntity3} {
		acc, err := ctrl.Staking.Account(ctx, &staking.OwnerQuery{Height: consensus.HeightLatest, Owner: addr})
		if err != nil {
			return err
		}
		if got, expected := acc.Escrow.CommissionSchedule, expectedSchedules[i]; !reflect.DeepEqual(expected, got) {
			return fmt.Errorf("unexpected commission schedule for entity: %d, expected: %v, got: %v", i+1, expected, got)
		}
	}

	return nil
}

func (n *minCommissionRateChecker) PostUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Ensure min commission rate was updated.
	params, err := ctrl.Staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	if params.CommissionScheduleRules.MinCommissionRate.Cmp(minCommissionRateChanges.MinCommissionRate) != 0 {
		return fmt.Errorf("expected zero min commission rate updated to: %v, got: %v", minCommissionRateChanges.MinCommissionRate, params.CommissionScheduleRules.MinCommissionRate)
	}
	// Ensure expected commission schedules exist.
	// All rates/bounds lower than the new MinCommissionRate should have been updated.
	expectedSchedules := []staking.CommissionSchedule{
		// Entity 1 updated rates.
		{
			Rates: []staking.CommissionRateStep{
				{
					Start: 0,
					Rate:  *minCommissionRateChanges.MinCommissionRate,
				},
			},
			Bounds: []staking.CommissionRateBoundStep{
				{
					Start:   0,
					RateMin: *minCommissionRateChanges.MinCommissionRate,
					RateMax: *quantity.NewFromUint64(100_000),
				},
				{
					Start:   200,
					RateMin: *minCommissionRateChanges.MinCommissionRate,
					RateMax: *quantity.NewFromUint64(90_000),
				},
			},
		},
		// Entity 2 updated rates.
		{
			Rates: []staking.CommissionRateStep{
				{
					Start: 0,
					Rate:  *quantity.NewFromUint64(60_000),
				},
			},
			Bounds: []staking.CommissionRateBoundStep{
				{
					Start:   0,
					RateMin: *minCommissionRateChanges.MinCommissionRate,
					RateMax: *quantity.NewFromUint64(100_000),
				},
			},
		},
		// Entity 3 updated rates.
		{
			Rates: []staking.CommissionRateStep{
				{
					Start: 0,
					Rate:  *minCommissionRateChanges.MinCommissionRate,
				},
				{
					Start: 100,
					Rate:  *minCommissionRateChanges.MinCommissionRate,
				},
				{
					Start: 800,
					Rate:  *minCommissionRateChanges.MinCommissionRate,
				},
			},
			Bounds: []staking.CommissionRateBoundStep{
				{
					Start:   0,
					RateMin: *minCommissionRateChanges.MinCommissionRate,
					RateMax: *quantity.NewFromUint64(100_000),
				},
				{
					Start:   500,
					RateMin: *minCommissionRateChanges.MinCommissionRate,
					RateMax: *minCommissionRateChanges.MinCommissionRate,
				},
			},
		},
	}
	for i, addr := range []staking.Address{DeterministicEntity1, DeterministicEntity2, DeterministicEntity3} {
		acc, err := ctrl.Staking.Account(ctx, &staking.OwnerQuery{Height: consensus.HeightLatest, Owner: addr})
		if err != nil {
			return err
		}
		if got, expected := acc.Escrow.CommissionSchedule, expectedSchedules[i]; !reflect.DeepEqual(expected, got) {
			return fmt.Errorf("unexpected commission schedule for entity: %d, expected: %v, got: %v", i+1, expected, got)
		}
	}
	return nil
}

// ChangeParametersMinCommissionRate is the governance change parameters scenario that
// changes minimum commission rate.
var ChangeParametersMinCommissionRate scenario.Scenario = newConsensusParameterUpgradeImpl(
	"change-parameters-min-commission-rate",
	&api.ChangeParametersProposal{
		Module:  staking.ModuleName,
		Changes: cbor.Marshal(minCommissionRateChanges),
	},
	&minCommissionRateChecker{},
)

type consensusParameterUpgradeImpl struct {
	Scenario

	parameters     *api.ChangeParametersProposal
	upgradeChecker upgradeChecker

	currentEpoch beacon.EpochTime
	entityNonce  uint64
	entity       *oasis.Entity
}

func newConsensusParameterUpgradeImpl(name string, parameters *api.ChangeParametersProposal, upgradeChecker upgradeChecker) scenario.Scenario {
	sc := &consensusParameterUpgradeImpl{
		Scenario:       *NewScenario(name),
		parameters:     parameters,
		upgradeChecker: upgradeChecker,
	}
	return sc
}

func (sc *consensusParameterUpgradeImpl) Clone() scenario.Scenario {
	return &consensusParameterUpgradeImpl{
		Scenario:       sc.Scenario.Clone(),
		parameters:     sc.parameters,
		upgradeChecker: sc.upgradeChecker,
		currentEpoch:   sc.currentEpoch,
		entityNonce:    sc.entityNonce,
	}
}

func (sc *consensusParameterUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
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
		TotalSupply: *quantity.NewFromUint64(1200),
		CommonPool:  *quantity.NewFromUint64(100),
		Parameters: staking.ConsensusParameters{
			CommissionScheduleRules: staking.CommissionScheduleRules{
				RateChangeInterval: 1,
				RateBoundLead:      1,
				MaxRateSteps:       10,
				MaxBoundSteps:      10,
				MinCommissionRate:  *quantity.NewFromUint64(0),
			},
		},
		Ledger: map[staking.Address]*staking.Account{
			// Fund entity account so we'll be able to submit the proposal.
			DeterministicEntity1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(1000),
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
					CommissionSchedule: entity1CommissionSchedule,
				},
			},
			DeterministicEntity2: {
				Escrow: staking.EscrowAccount{
					CommissionSchedule: entity2CommissionSchedule,
				},
			},
			DeterministicEntity3: {
				Escrow: staking.EscrowAccount{
					CommissionSchedule: entity3CommissionSchedule,
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			DeterministicEntity1: {
				DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
		},
	}
	f.Entities = []oasis.EntityCfg{
		{IsDebugTestEntity: true},
		{},
	}

	return f, nil
}

func (sc *consensusParameterUpgradeImpl) nextEpoch(ctx context.Context) error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(ctx, sc.currentEpoch); err != nil {
		// Errors can happen because an upgrade happens exactly during an epoch transition. So
		// make sure to ignore them.
		sc.Logger.Warn("failed to set epoch",
			"epoch", sc.currentEpoch,
			"err", err,
		)
	}
	return nil
}

func (sc *consensusParameterUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
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

	if err := sc.nextEpoch(ctx); err != nil {
		return err
	}

	sc.entity = sc.Net.Entities()[1]
	entityAcc, err := sc.Net.Controller().Staking.Account(ctx,
		&staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  DeterministicEntity1,
		},
	)
	if err != nil {
		return fmt.Errorf("failed querying account: %w", err)
	}
	sc.entityNonce = entityAcc.General.Nonce

	// Run pre-upgrade checker.
	sc.Logger.Info("running pre-upgrade checks")
	if err = sc.upgradeChecker.PreUpgradeFn(ctx, sc.Net.Controller()); err != nil {
		return err
	}

	// Submit change parameters proposal.
	content := &api.ProposalContent{
		ChangeParameters: sc.parameters,
	}
	_, sc.entityNonce, sc.currentEpoch, err = sc.EnsureProposalFinalized(ctx, content, sc.entity, sc.entityNonce, sc.currentEpoch)
	if err != nil {
		return fmt.Errorf("upgrade proposal error: %w", err)
	}

	// Run post-upgrade checker.
	sc.Logger.Info("running post-upgrade checks")
	if err = sc.upgradeChecker.PostUpgradeFn(ctx, sc.Net.Controller()); err != nil {
		return err
	}

	// Do one final epoch transition.
	sc.Logger.Info("final epoch transition")
	if err = sc.nextEpoch(ctx); err != nil {
		return err
	}

	return nil
}
