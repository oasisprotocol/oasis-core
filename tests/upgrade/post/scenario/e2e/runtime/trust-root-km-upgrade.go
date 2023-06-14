package runtime

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e/runtime"

	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e"
)

var (
	// TrustRootKeymanagerUpgrade is the keymanager upgrade post-upgrade scenario.
	TrustRootKeymanagerUpgrade scenario.Scenario = newTrustRootKeymanagerUpgradeImpl()

	trustRootKeymanagerUpgradeTestClientScenario = runtime.NewTestClientScenario([]interface{}{
		runtime.GetKeyValueTx{Key: "key1", Response: "value1", Encrypted: false},
		runtime.GetKeyValueTx{Key: "key1", Response: "", Encrypted: true},
		runtime.GetKeyValueTx{Key: "key2", Response: "", Encrypted: false},
		runtime.GetKeyValueTx{Key: "key2", Response: "value2", Encrypted: true},
	})
)

type trustRootKeymanagerUpgradeImpl struct {
	runtime.KmUpgradeImpl
}

func newTrustRootKeymanagerUpgradeImpl() scenario.Scenario {
	return &trustRootKeymanagerUpgradeImpl{
		KmUpgradeImpl: runtime.KmUpgradeImpl{
			Scenario: *runtime.NewScenario(
				"trust-root/keymanager-upgrade",
				runtime.NewKVTestClient().WithSeed("seed3").WithScenario(trustRootKeymanagerUpgradeTestClientScenario),
			),
		},
	}
}

func (sc *trustRootKeymanagerUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.KmUpgradeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use the same non-debug entity as in the pre-upgrade scenario.
	f.Entities[1].Restore = true

	return f, nil
}

func (sc *trustRootKeymanagerUpgradeImpl) Clone() scenario.Scenario {
	return &trustRootKeymanagerUpgradeImpl{
		KmUpgradeImpl: *sc.KmUpgradeImpl.Clone().(*runtime.KmUpgradeImpl),
	}
}

func (sc *trustRootKeymanagerUpgradeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()

	// Fix the exported genesis file and use it.
	genesisFile, err := e2e.FixExportedGenesisFile(childEnv, &sc.Scenario.Scenario)
	if err != nil {
		return err
	}
	cfg := sc.Net.Config()
	cfg.GenesisFile = genesisFile

	// Start the network.
	if err = sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Add the upgraded key manager node to the entity.
	if err = sc.registerEntity(ctx, childEnv, sc.Net.Entities()[1]); err != nil {
		return err
	}

	// Run upgrade scenario.
	if err = sc.KmUpgradeImpl.Run(childEnv); err != nil {
		return err
	}

	return nil
}

func (sc *trustRootKeymanagerUpgradeImpl) registerEntity(ctx context.Context, childEnv *env.Env, ent *oasis.Entity) error {
	nonce, err := sc.GetEntityNonceByID(ctx, ent.ID())
	if err != nil {
		return nil
	}

	cli := cli.New(childEnv, sc.Net, sc.Logger)
	path := filepath.Join(childEnv.Dir(), "register_entity.json")
	if err = cli.Registry.GenerateRegisterEntityTx(ent.Dir(), nonce, path); err != nil {
		return fmt.Errorf("failed to generate register entity tx: %w", err)
	}
	if err = cli.Consensus.SubmitTx(path); err != nil {
		return fmt.Errorf("failed to submit register entity tx: %w", err)
	}

	return nil
}
