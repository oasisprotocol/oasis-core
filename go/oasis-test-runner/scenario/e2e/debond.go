package e2e

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// Debond tests debonding records created in the genesis document.
var Debond scenario.Scenario = &debondImpl{
	runtimeImpl: *newRuntimeImpl("debond", "", nil),
}

type debondImpl struct {
	runtimeImpl
}

func (s *debondImpl) Clone() scenario.Scenario {
	return &debondImpl{
		runtimeImpl: *s.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (s *debondImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.EpochtimeMock = true

	// Enable some features in the staking system that we'll test.
	f.Network.StakingGenesis = "tests/fixture-data/debond/staking-genesis.json"

	return f, nil
}

func (s *debondImpl) Run(*env.Env) error {
	if err := s.net.Start(); err != nil {
		return fmt.Errorf("net Start: %w", err)
	}

	ctx := context.Background()

	s.logger.Info("waiting for network to come up")
	if err := s.net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	// Beginning: lockup account has no funds.
	lockupQuery := staking.OwnerQuery{
		Height: consensus.HeightLatest,
	}
	if err := lockupQuery.Owner.UnmarshalHex("5555555555555555555555555555555555555555555555555555555555555555"); err != nil {
		return fmt.Errorf("import lockup account ID: %w", err)
	}
	s.logger.Info("checking balance at beginning")
	acct, err := s.net.Controller().Staking.AccountInfo(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("beginning AccountInfo: %w", err)
	}
	if !acct.General.Balance.IsZero() {
		return fmt.Errorf("beginning balance %v should be zero", acct.General.Balance)
	}
	s.logger.Info("balance ok")

	// First debonding: 500 tokens at epoch 1.
	s.logger.Info("advancing to first debonding")
	if err = s.net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("first SetEpoch: %w", err)
	}
	var expected quantity.Quantity
	if err = expected.FromInt64(500); err != nil {
		return fmt.Errorf("import first debonding expected balance: %w", err)
	}
	s.logger.Info("checking balance at first debonding")
	acct, err = s.net.Controller().Staking.AccountInfo(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("first debonding AccountInfo: %w", err)
	}
	if acct.General.Balance.Cmp(&expected) != 0 {
		return fmt.Errorf("first debonding balance %v should be %v", acct.General.Balance, expected)
	}
	s.logger.Info("balance ok")

	// Second debonding: 500 more tokens at epoch 2.
	s.logger.Info("advancing to second debonding")
	if err = s.net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("second SetEpoch: %w", err)
	}
	if err = expected.FromInt64(1000); err != nil {
		return fmt.Errorf("import second debonding expected balance: %w", err)
	}
	s.logger.Info("checking balance at second debonding")
	acct, err = s.net.Controller().Staking.AccountInfo(ctx, &lockupQuery)
	if err != nil {
		return fmt.Errorf("second debonding AccountInfo: %w", err)
	}
	if acct.General.Balance.Cmp(&expected) != 0 {
		return fmt.Errorf("second debonding balance %v should be %v", acct.General.Balance, expected)
	}
	s.logger.Info("balance ok")

	return nil
}
