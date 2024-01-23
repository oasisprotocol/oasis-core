package e2e

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/oasisprotocol/oasis-core/go/config"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// SeedAPI is the scenario where seed node control and consensus APIs are tested.
var SeedAPI scenario.Scenario = &seedAPI{
	Scenario: *NewScenario("seed-api"),
}

type seedAPI struct {
	Scenario
}

func (sc *seedAPI) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Add a client which will connect to the seed.
	f.Clients = append(f.Clients, oasis.ClientFixture{})

	f.Network.SetInsecureBeacon()

	return f, nil
}

func (sc *seedAPI) Clone() scenario.Scenario {
	return &seedAPI{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *seedAPI) Run(ctx context.Context, _ *env.Env) error { // nolint: gocyclo
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("net Start: %w", err)
	}

	sc.Logger.Info("waiting for network to come up")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	seedCtrl, err := oasis.NewController(sc.Net.Seeds()[0].SocketPath())
	if err != nil {
		return err
	}

	// Unimplemented node controller methods.
	sc.Logger.Info("testing WaitSync")
	if err = seedCtrl.WaitSync(ctx); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node WaitSync should fail with not implemented error")
	}

	sc.Logger.Info("testing IsSynced")
	if _, err = seedCtrl.IsSynced(ctx); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node IsSynced should fail with not implemented error")
	}

	sc.Logger.Info("testing WaitReady")
	if err = seedCtrl.WaitReady(ctx); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node WaitReady should fail with not implemented error")
	}

	sc.Logger.Info("testing IsReady")
	if _, err = seedCtrl.IsReady(ctx); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node IsReady should fail with not implemented error")
	}

	sc.Logger.Info("testing UpgradeBinary")
	if err = seedCtrl.UpgradeBinary(ctx, nil); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node UpgradeBinary should fail with not implemented error")
	}

	sc.Logger.Info("testing CancelUpgrade")
	if err = seedCtrl.CancelUpgrade(ctx, nil); !errors.Is(err, control.ErrNotImplemented) {
		return fmt.Errorf("seed node CancelUpgrade should fail with not implemented error")
	}

	// Implemented node controller methods.
	sc.Logger.Info("testing GetStatus")
	status, err := seedCtrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for seed node: %w", err)
	}

	// Unsupported status fields.
	if status.Debug != nil {
		return fmt.Errorf("seed node should not report debug status")
	}
	if status.Consensus != nil {
		return fmt.Errorf("seed node should not report consensus status")
	}
	if status.Runtimes != nil {
		return fmt.Errorf("seed node should not run any runtimes")
	}
	if status.Registration != nil {
		return fmt.Errorf("seed node should not register")
	}
	if status.Keymanager != nil {
		return fmt.Errorf("seed node should not run key manager")
	}
	if status.PendingUpgrades != nil {
		return fmt.Errorf("seed node should not have pending upgrades")
	}

	// General status fields.
	if status.SoftwareVersion == "" {
		return fmt.Errorf("seed node should report software version")
	}
	if status.Mode != config.ModeSeed {
		return fmt.Errorf("seed node should report its mode, got: %v", status.Mode)
	}
	if reflect.DeepEqual(status.Identity, control.IdentityStatus{}) {
		return fmt.Errorf("seed node should report its identity")
	}

	// Seed node specific status fields.
	if status.Seed.ChainContext == "" {
		return fmt.Errorf("seed node should report chain context")
	}
	if len(status.Seed.Addresses) == 0 {
		return fmt.Errorf("seed node should have at least one address")
	}
	if len(status.Seed.NodePeers) == 0 {
		return fmt.Errorf("seed node should be connected at least to the client-0")
	}

	// Graceful shutdown.
	sc.Logger.Info("testing RequestShutdown")
	if err := seedCtrl.RequestShutdown(ctx, true); err != nil {
		return fmt.Errorf("seed node request shutdown error: %w", err)
	}

	return nil
}
