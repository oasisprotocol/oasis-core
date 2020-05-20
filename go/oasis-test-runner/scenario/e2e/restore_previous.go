package e2e

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

// RestoreV206 tests restoring from a v20.6 genesis document.
var RestoreV206 scenario.Scenario = &restorePrevious{
	runtimeImpl: *newRuntimeImpl("restore-v206", "simple-keyvalue-client", nil),
	// Use the genesis document from v20.6 E2E tests (scenario: e2e/runtime/runtime).
	genesisFile: "tests/fixture-data/restore-previous/genesis-v20.6.json",
}

type restorePrevious struct {
	runtimeImpl

	genesisFile string
}

func (sc *restorePrevious) Clone() scenario.Scenario {
	return &restorePrevious{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
		genesisFile: sc.genesisFile,
	}
}

func (sc *restorePrevious) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	if sc.genesisFile == "" {
		return nil, fmt.Errorf("genesis file not specified in scenario")
	}
	f.Network.GenesisFile = sc.genesisFile
	// Use deterministic identities so we can use the same keys.
	f.Network.DeterministicIdentities = true

	return f, nil
}

func (sc *restorePrevious) Run(childEnv *env.Env) error {
	// Restore tests use a fixed genesis that only works on non-TEE environments.
	if sc.TEEHardware != "" {
		sc.logger.Info("skipping test due to incompatible TEE hardware")
		return nil
	}
	return sc.runtimeImpl.Run(childEnv)
}
