package e2e

import (
	"context"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// GasFeesRuntimes is the runtime gas fees scenario.
	GasFeesRuntimes scenario.Scenario = &gasFeesRuntimesImpl{
		basicImpl: *newBasicImpl("gas-fees/runtimes", "", nil),
	}
)

// gasPrice is the gas price used during the test.
const gasPrice = 1

type gasFeesRuntimesImpl struct {
	basicImpl
}

func (sc *gasFeesRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use deterministic identities as we need to allocate funds to nodes.
	f.Network.DeterministicIdentities = true
	// Give our nodes some tokens.
	f.Network.StakingGenesis = "tests/fixture-data/gas-fees-runtimes/staking-genesis.json"
	// Update validators to require fee payments.
	for i := range f.Validators {
		f.Validators[i].MinGasPrice = gasPrice
		f.Validators[i].SubmissionGasPrice = gasPrice
	}
	// Update all other nodes to use a specific gas price.
	for i := range f.Keymanagers {
		f.Keymanagers[i].SubmissionGasPrice = gasPrice
	}
	for i := range f.StorageWorkers {
		f.StorageWorkers[i].SubmissionGasPrice = gasPrice
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].SubmissionGasPrice = gasPrice
	}
	for i := range f.ByzantineNodes {
		f.ByzantineNodes[i].SubmissionGasPrice = gasPrice
	}

	return f, nil
}

func (sc *gasFeesRuntimesImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether transaction processing works.
	sc.logger.Info("submitting transaction to runtime")
	if err := sc.submitRuntimeTx(ctx, runtimeID, "hello", "non-free world"); err != nil {
		return err
	}

	return nil
}
