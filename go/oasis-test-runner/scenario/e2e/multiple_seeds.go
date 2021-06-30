package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// MultipleSeeds is the scenario where multiple seed nodes are used.
var MultipleSeeds scenario.Scenario = &multipleSeeds{
	E2E: *NewE2E("multiple-seeds"),
}

type multipleSeeds struct {
	E2E
}

func (sc *multipleSeeds) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	f.Seeds = []oasis.SeedFixture{
		// Disable populating address book from genesis, so we also test
		// including new peers.
		{DisableAddrBookFromGenesis: true},
		{DisableAddrBookFromGenesis: true},
		{DisableAddrBookFromGenesis: true},
	}

	f.Network.SetInsecureBeacon()

	return f, nil
}

func (sc *multipleSeeds) Clone() scenario.Scenario {
	return &multipleSeeds{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *multipleSeeds) Run(childEnv *env.Env) error { // nolint: gocyclo
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("net Start: %w", err)
	}

	ctx := context.Background()

	sc.Logger.Info("waiting for network to come up")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	return nil
}
