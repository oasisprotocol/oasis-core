package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Debond tests debonding records created in the genesis document.
var Debond scenario.Scenario = &debondImpl{
	E2E: *NewE2E("debond"),
}

type debondImpl struct {
	E2E
}

func (s *debondImpl) Clone() scenario.Scenario {
	return &debondImpl{
		E2E: s.E2E.Clone(),
	}
}

func (s *debondImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.SetMockEpoch()
	f.Network.SetInsecureBeacon()

	// Enable some features in the staking system that we'll test.
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			CommissionScheduleRules: staking.CommissionScheduleRules{
				RateChangeInterval: 10,
				RateBoundLead:      30,
				MaxRateSteps:       4,
				MaxBoundSteps:      12,
			},
		},
		TotalSupply: *quantity.NewFromUint64(1000),
		Ledger: map[staking.Address]*staking.Account{
			TestEntityAccount: {
				Escrow: staking.EscrowAccount{
					Debonding: staking.SharePool{
						Balance:     *quantity.NewFromUint64(1000),
						TotalShares: *quantity.NewFromUint64(1000),
					},
				},
			},
		},
		DebondingDelegations: map[staking.Address]map[staking.Address][]*staking.DebondingDelegation{
			TestEntityAccount: {
				DeterministicValidator0: {
					{
						Shares:        *quantity.NewFromUint64(500),
						DebondEndTime: 1,
					},
					{
						Shares:        *quantity.NewFromUint64(500),
						DebondEndTime: 2,
					},
				},
			},
		},
	}

	return f, nil
}

func (s *debondImpl) Run(*env.Env) error {
	if err := s.Net.Start(); err != nil {
		return fmt.Errorf("net Start: %w", err)
	}

	ctx := context.Background()

	s.Logger.Info("waiting for network to come up")
	if err := s.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	// Beginning: lockup account has no funds.
	lockupQuery := staking.OwnerQuery{
		Owner:  DeterministicValidator0,
		Height: consensus.HeightLatest,
	}
	s.Logger.Info("checking balance at beginning")
	acct, err := s.Net.Controller().Staking.Account(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("beginning Account: %w", err)
	}
	if !acct.General.Balance.IsZero() {
		return fmt.Errorf("beginning balance %v should be zero", acct.General.Balance)
	}
	s.Logger.Info("balance ok")

	// First debonding: 500 base units at epoch 1.
	s.Logger.Info("advancing to first debonding")
	if err = s.Net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("first SetEpoch: %w", err)
	}
	var expected quantity.Quantity
	if err = expected.FromInt64(500); err != nil {
		return fmt.Errorf("import first debonding expected balance: %w", err)
	}
	s.Logger.Info("checking balance at first debonding")
	acct, err = s.Net.Controller().Staking.Account(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("first debonding Account: %w", err)
	}
	if acct.General.Balance.Cmp(&expected) != 0 {
		return fmt.Errorf("first debonding balance %v should be %v", acct.General.Balance, expected)
	}
	s.Logger.Info("balance ok")

	// Second debonding: 500 more base units at epoch 2.
	s.Logger.Info("advancing to second debonding")
	if err = s.Net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("second SetEpoch: %w", err)
	}
	if err = expected.FromInt64(1000); err != nil {
		return fmt.Errorf("import second debonding expected balance: %w", err)
	}
	s.Logger.Info("checking balance at second debonding")
	acct, err = s.Net.Controller().Staking.Account(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("second debonding Account: %w", err)
	}
	if acct.General.Balance.Cmp(&expected) != 0 {
		return fmt.Errorf("second debonding balance %v should be %v", acct.General.Balance, expected)
	}
	s.Logger.Info("balance ok")

	return nil
}
