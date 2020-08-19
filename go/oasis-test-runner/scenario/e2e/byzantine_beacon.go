package e2e

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/byzantine"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// ByzantineBeaconHonest is the honest byzantine beacon scenario.
	ByzantineBeaconHonest scenario.Scenario = &byzantineBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-honest"),
		extraArgs: []string{
			"--" + byzantine.CfgBeaconMode, byzantine.ModeBeaconHonest.String(),
		},
		identitySeed: oasis.ByzantineDefaultIdentitySeed,
	}

	// ByzantineBeaconCommitStraggler is the commit straggler byzantine beacon scenario.
	ByzantineBeaconCommitStraggler scenario.Scenario = &byzantineBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-commit-straggler"),
		extraArgs: []string{
			"--" + byzantine.CfgBeaconMode, byzantine.ModeBeaconCommitStraggler.String(),
		},
		identitySeed: oasis.ByzantineDefaultIdentitySeed,
	}

	// ByzantineBeaconRevealStraggler is the reveal straggler byzantine beacon scenario.
	ByzantineBeaconRevealStraggler scenario.Scenario = &byzantineBeaconImpl{
		E2E: *NewE2E("byzantine/beacon-reveal-straggler"),
		extraArgs: []string{
			"--" + byzantine.CfgBeaconMode, byzantine.ModeBeaconRevealStraggler.String(),
		},
		identitySeed: oasis.ByzantineDefaultIdentitySeed,
	}
)

type byzantineBeaconImpl struct {
	E2E

	extraArgs    []string
	identitySeed string
}

func (sc *byzantineBeaconImpl) Clone() scenario.Scenario {
	return &byzantineBeaconImpl{
		E2E:          sc.E2E.Clone(),
		extraArgs:    sc.extraArgs,
		identitySeed: sc.identitySeed,
	}
}

func (sc *byzantineBeaconImpl) Fixture() (*oasis.NetworkFixture, error) {
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
			Script:          "beacon",
			ExtraArgs:       sc.extraArgs,
			IdentitySeed:    sc.identitySeed,
			Entity:          1,
			ActivationEpoch: 1,
		},
	}

	// Use really ugly hacks to force the byzantine node to participate.
	if l := len(f.ByzantineNodes); l != 1 {
		return nil, fmt.Errorf("byzantine/beacon: unexpected number of byzantine nodes: %d", l)
	}
	node := f.ByzantineNodes[0]
	pks, err := oasis.GenerateDeterministicNodeKeys(nil, node.IdentitySeed, []signature.SignerRole{signature.SignerNode})
	if err != nil {
		return nil, fmt.Errorf("byzantine/beacon: failed to derive node identity: %w", err)
	}
	f.Network.Beacon.PVSSParameters = &beacon.PVSSParameters{
		DebugForcedParticipants: []signature.PublicKey{
			pks[0],
		},
	}

	// Make sure the byzantine node does at least 1 round (in)correctly.
	f.ByzantineNodes[0].LogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertEvent(byzantine.LogEventBeaconRoundCompleted, "byzantine node executed no rounds"),
	}

	return f, nil
}

func (sc *byzantineBeaconImpl) Run(childEnv *env.Env) error {
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
