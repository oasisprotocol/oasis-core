package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const byzantineBeaconIdentitySeed = "ekiden byzantine node worker"

var (
	// ByzantineVRFBeaconHonest is the honest byzantine VRF beacon scenario.
	ByzantineVRFBeaconHonest scenario.Scenario = &byzantineVRFBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-vrf-honest"),
		extraArgs: []oasis.Argument{
			{Name: byzantine.CfgVRFBeaconMode, Values: []string{byzantine.ModeVRFBeaconHonest.String()}},
		},
		identitySeed: byzantineBeaconIdentitySeed,
	}

	// ByzantineVRFBeaconEarly is the early-proof byzantine beacon scenario.
	ByzantineVRFBeaconEarly scenario.Scenario = &byzantineVRFBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-vrf-early"),
		extraArgs: []oasis.Argument{
			{Name: byzantine.CfgVRFBeaconMode, Values: []string{byzantine.ModeVRFBeaconEarly.String()}},
		},
		identitySeed: byzantineBeaconIdentitySeed,
	}

	// ByzantineVRFBeaconMissing is the missing-proof byzantine beacon scenario.
	ByzantineVRFBeaconMissing scenario.Scenario = &byzantineVRFBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-vrf-missing"),
		extraArgs: []oasis.Argument{
			{Name: byzantine.CfgVRFBeaconMode, Values: []string{byzantine.ModeVRFBeaconMissing.String()}},
		},
		identitySeed: byzantineBeaconIdentitySeed,
	}
)

type byzantineVRFBeaconImpl struct {
	E2E

	extraArgs    []oasis.Argument
	identitySeed string
}

func (sc *byzantineVRFBeaconImpl) Clone() scenario.Scenario {
	return &byzantineVRFBeaconImpl{
		E2E:          sc.E2E.Clone(),
		extraArgs:    sc.extraArgs,
		identitySeed: sc.identitySeed,
	}
}

func (sc *byzantineVRFBeaconImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.SetMockEpoch()
	// Provision a Byzantine node.
	f.ByzantineNodes = []oasis.ByzantineFixture{
		{
			Script:          "vrfbeacon",
			ExtraArgs:       sc.extraArgs,
			IdentitySeed:    sc.identitySeed,
			Entity:          1,
			ActivationEpoch: 1,
			Runtime:         -1,
		},
	}

	// Use really ugly hacks to force the byzantine node to participate.
	if l := len(f.ByzantineNodes); l != 1 {
		return nil, fmt.Errorf("byzantine/beacon: unexpected number of byzantine nodes: %d", l)
	}

	// Make sure the byzantine node does at least 1 round (in)correctly.
	f.ByzantineNodes[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertEvent(byzantine.LogEventVRFBeaconRoundCompleted, "byzantine node executed no rounds"),
	}

	return f, nil
}

func (sc *byzantineVRFBeaconImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	// Wait for the validators to come up.
	sc.Logger.Info("waiting for validators to initialize",
		"num_validators", len(sc.Net.Validators()),
	)
	for _, n := range sc.Net.Validators() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}
	sc.Logger.Info("triggering epoch transition")
	if err := sc.Net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.Logger.Info("epoch transition done")

	// Wait for the byzantine node to register.
	sc.Logger.Info("waiting for (all) nodes to register",
		"num_nodes", sc.Net.NumRegisterNodes(),
	)
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("failed to wait for nodes: %w", err)
	}

	// Trigger an epoch transition to start the beacon round.
	sc.Logger.Info("triggering epoch transition - start beacon round")
	if err := sc.Net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.Logger.Info("epoch transition done")

	// Trigger an epoch transition so that we wait for the beacon round.
	sc.Logger.Info("triggering epoch transition - finish beacon round")
	if err := sc.Net.Controller().SetEpoch(ctx, 3); err != nil {
		return err
	}
	sc.Logger.Info("epoch transition done")

	// Make sure the byzantine beacon did the right thing.
	return sc.Net.CheckLogWatchers()
}
