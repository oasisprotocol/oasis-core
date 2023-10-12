package runtime

import (
	"context"

	"github.com/hashicorp/go-multierror"

	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e/runtime"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"

	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e"
)

var (
	// SecureUpgrade is a pre-upgrade part of the scenario in which we upgrade
	// the simple key/value and key manager runtimes, utilize trust roots for
	// consensus verification, and test the functionality of master secret rotations.
	SecureUpgrade scenario.Scenario = newSecureUpgradeImpl()

	// nodeUpgradeTestClientScenario tests that everything works before the upgrade starts.
	nodeUpgradeTestClientScenario = runtime.NewTestClientScenario([]interface{}{
		runtime.InsertKeyValueTx{Key: "node-key1", Value: "node-value1", Response: "", Encrypted: false},
		runtime.InsertKeyValueTx{Key: "node-key2", Value: "node-value2", Response: "", Encrypted: true},
		runtime.GetKeyValueTx{Key: "node-key1", Response: "node-value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "node-key2", Response: "node-value2", Encrypted: true},
		runtime.GetKeyValueTx{Key: "node-key1", Response: "", Encrypted: true},
		runtime.GetKeyValueTx{Key: "node-key2", Response: "", Encrypted: false},
	})
)

type secureUpgradeImpl struct {
	runtime.TrustRootImpl
}

func newSecureUpgradeImpl() scenario.Scenario {
	return &secureUpgradeImpl{
		TrustRootImpl: *runtime.NewTrustRootImpl(
			"secure-upgrade",
			runtime.NewKVTestClient().WithScenario(nodeUpgradeTestClientScenario),
		),
	}
}

func (sc *secureUpgradeImpl) Clone() scenario.Scenario {
	return &secureUpgradeImpl{
		TrustRootImpl: *sc.TrustRootImpl.Clone().(*runtime.TrustRootImpl),
	}
}

func (sc *secureUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.TrustRootImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Ensure entities can vote.
	f.Network.FundEntities = true
	f.Network.StakingGenesis = &staking.Genesis{}

	// Speed up voting.
	f.Network.GovernanceParameters = &governance.ConsensusParameters{
		StakeThreshold:            67,
		UpgradeCancelMinEpochDiff: 3,
		UpgradeMinEpochDiff:       3,
		VotingPeriod:              2,
	}

	// Keep runtime bundles for post-upgrade scenario.
	for i := range f.Runtimes {
		f.Runtimes[i].KeepBundles = true
	}

	return f, nil
}

func (sc *secureUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) (err error) {
	// Build the simple key/value runtime and the simple key manager runtime with an embedded
	// trust root, start the network, register the runtimes and run the test client.
	defer func() {
		err2 := sc.PostRun(ctx, childEnv)
		err = multierror.Append(err, err2).ErrorOrNil()
	}()
	if err = sc.PreRun(ctx, childEnv); err != nil {
		return err
	}

	// The test client has already inserted encrypted values into the database. These values
	// can now be utilized in the post-upgrade scenario to verify the preservation of the key
	// manager's master secret and to ensure that runtime key derivation remained unchanged.

	// Upgrade the network and wait for it to halt.
	if err := e2e.DumpRestoreUpgradeNetwork(ctx, childEnv, &sc.Scenario.Scenario); err != nil {
		return err
	}

	return nil
}
