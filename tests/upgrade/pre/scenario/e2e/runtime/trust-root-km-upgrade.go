package runtime

import (
	"context"
	"fmt"

	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e/runtime"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"

	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e"
)

var (
	// TrustRootKeymanagerUpgrade is the keymanager upgrade pre-upgrade scenario.
	TrustRootKeymanagerUpgrade scenario.Scenario = newTrustRootKeymanagerUpgradeImpl()

	trustRootKeymanagerUpgradeTestClientScenario = runtime.NewTestClientScenario([]interface{}{
		runtime.RuntimeInsertKeyValueTx{Key: "key1", Value: "value1", Response: "", Encrypted: false},
		runtime.RuntimeInsertKeyValueTx{Key: "key2", Value: "value2", Response: "", Encrypted: true},
		runtime.RuntimeGetKeyValueTx{Key: "key1", Response: "value1", Encrypted: false},
		runtime.RuntimeGetKeyValueTx{Key: "key1", Response: "", Encrypted: true},
		runtime.RuntimeGetKeyValueTx{Key: "key2", Response: "", Encrypted: false},
		runtime.RuntimeGetKeyValueTx{Key: "key2", Response: "value2", Encrypted: true},
	})
)

type trustRootKeymanagerUpgradeImpl struct {
	runtime.TrustRootImpl
}

func newTrustRootKeymanagerUpgradeImpl() scenario.Scenario {
	return &trustRootKeymanagerUpgradeImpl{
		TrustRootImpl: *runtime.NewTrustRootImpl(
			"keymanager-upgrade",
			runtime.NewTestClient().WithScenario(trustRootKeymanagerUpgradeTestClientScenario),
		),
	}
}

func (sc *trustRootKeymanagerUpgradeImpl) Clone() scenario.Scenario {
	return &trustRootKeymanagerUpgradeImpl{
		TrustRootImpl: *sc.TrustRootImpl.Clone().(*runtime.TrustRootImpl),
	}
}

func (sc *trustRootKeymanagerUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
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

func (sc *trustRootKeymanagerUpgradeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()

	// Build a simple key/value runtime with embedded trust root, start the network, register
	// runtimes and run the test client.
	rebuild, err := sc.BuildRuntimeBinary(ctx, childEnv)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := rebuild(); err2 != nil {
			err = fmt.Errorf("%w (original error: %s)", err2, err)
		}
	}()

	// Upgrade the network and wait for it to halt.
	if err := e2e.DumpRestoreUpgradeNetwork(ctx, childEnv, &sc.E2E); err != nil {
		return err
	}

	return nil
}
