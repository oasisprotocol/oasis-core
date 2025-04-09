package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

var (
	roflScenario         = newROFLScenario("0.0.0")
	roflUpgradedScenario = newROFLScenario("0.1.0")
)

func newROFLScenario(version string) TestClientScenario {
	return NewTestClientScenario([]any{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
		RemoveKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key", "", 0, 0, encryptedWithSecretsTxKind},
		// Check that the ROFL component wrote the HTTP response into storage.
		GetKeyValueTx{"rofl_version", version, 0, 0, plaintextTxKind},
		KeyExistsTx{"rofl_http", 0, 0, plaintextTxKind},
	})
}

// ROFL is the runtime with a ROFL component scenario.
var ROFL scenario.Scenario = newROFL()

type roflImpl struct {
	Scenario
}

func newROFL() scenario.Scenario {
	return &roflImpl{
		Scenario: *NewScenario("rofl", NewTestClient().WithScenario(roflScenario)),
	}
}

func (sc *roflImpl) Clone() scenario.Scenario {
	return &roflImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *roflImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Add ROFL component.
	f.Runtimes[1].Deployments[0].Components = append(f.Runtimes[1].Deployments[0].Components, oasis.ComponentCfg{
		Kind:     component.ROFL,
		Name:     "test-rofl",
		Binaries: sc.ResolveRuntimeBinaries(ROFLComponentBinary),
	})

	// Prepare upgraded ROFL component in a separate bundle.
	f.Runtimes[1].Deployments = append(f.Runtimes[1].Deployments, oasis.DeploymentCfg{
		ValidFrom: api.EpochMax,
		Components: []oasis.ComponentCfg{
			{
				Kind:     component.ROFL,
				Name:     "test-rofl",
				Version:  version.Version{Major: 0, Minor: 1, Patch: 0},
				Binaries: sc.ResolveRuntimeBinaries(ROFLComponentUpgradeBinary),
			},
		},
		ExcludeBundle: true,
	})

	return f, nil
}

func (sc *roflImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Test ROFL component.
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	if err := sc.WaitTestClientAndCheckLogs(); err != nil {
		return err
	}

	// Upgrade ROFL component.
	sc.Logger.Info("upgrading ROFL component")

	path := sc.Net.Runtimes()[1].BundlePath(1)
	for _, w := range sc.Net.ComputeWorkers() {
		ctrl, err := oasis.NewController(w.SocketPath())
		if err != nil {
			return err
		}
		if err = ctrl.AddBundle(ctx, path); err != nil {
			return err
		}
	}

	// Test upgraded ROFL component.
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(roflUpgradedScenario)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
