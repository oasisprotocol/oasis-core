package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// GasFeesRuntimes is the runtime gas fees scenario.
var GasFeesRuntimes scenario.Scenario = &gasFeesRuntimesImpl{
	runtimeImpl: *newRuntimeImpl("gas-fees/runtimes", nil),
}

// gasPrice is the gas price used during the test.
const gasPrice = 1

type gasFeesRuntimesImpl struct {
	runtimeImpl
}

func (sc *gasFeesRuntimesImpl) Clone() scenario.Scenario {
	return &gasFeesRuntimesImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *gasFeesRuntimesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use deterministic identities as we need to allocate funds to nodes.
	f.Network.DeterministicIdentities = true
	// Give our nodes some stake.
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			FeeSplitWeightPropose:     *quantity.NewFromUint64(2),
			FeeSplitWeightVote:        *quantity.NewFromUint64(1),
			FeeSplitWeightNextPropose: *quantity.NewFromUint64(1),
		},
		TotalSupply: *quantity.NewFromUint64(90000000),
		Ledger: map[staking.Address]*staking.Account{
			e2e.DeterministicValidator0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicValidator1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicValidator2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicCompute0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicCompute1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicCompute2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicStorage0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicStorage1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
			e2e.DeterministicKeyManager0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000),
				},
			},
		},
	}
	// Update validators to require fee payments.
	for i := range f.Validators {
		f.Validators[i].Consensus.MinGasPrice = gasPrice
		f.Validators[i].Consensus.SubmissionGasPrice = gasPrice
	}
	// Update all other nodes to use a specific gas price.
	for i := range f.Keymanagers {
		f.Keymanagers[i].Consensus.SubmissionGasPrice = gasPrice
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].Consensus.SubmissionGasPrice = gasPrice
	}
	for i := range f.ByzantineNodes {
		f.ByzantineNodes[i].Consensus.SubmissionGasPrice = gasPrice
	}

	return f, nil
}

func (sc *gasFeesRuntimesImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether transaction processing works.
	sc.Logger.Info("submitting transaction to runtime")
	if _, err := sc.submitKeyValueRuntimeInsertTx(ctx, runtimeID, "hello", "non-free world", 0); err != nil {
		return err
	}

	return nil
}
