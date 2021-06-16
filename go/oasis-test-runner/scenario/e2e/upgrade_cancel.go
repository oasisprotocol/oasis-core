package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const upgradeHandler = "__e2e-test-upgrade-cancel"

// NodeUpgradeCancel is the node upgrade scenario.
var NodeUpgradeCancel scenario.Scenario = newNodeUpgradeCancelImpl()

type nodeUpgradeCancelImpl struct {
	E2E

	ctx          context.Context
	currentEpoch beacon.EpochTime
}

func (sc *nodeUpgradeCancelImpl) nextEpoch() error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(sc.ctx, sc.currentEpoch); err != nil {
		return fmt.Errorf("failed to set epoch to %d: %w", sc.currentEpoch, err)
	}
	return nil
}

func newNodeUpgradeCancelImpl() scenario.Scenario {
	sc := &nodeUpgradeCancelImpl{
		E2E: *NewE2E("node-upgrade-cancel"),
		ctx: context.Background(),
	}
	return sc
}

func (sc *nodeUpgradeCancelImpl) Clone() scenario.Scenario {
	return &nodeUpgradeCancelImpl{
		E2E: sc.E2E.Clone(),
		ctx: context.Background(),
	}
}

func (sc *nodeUpgradeCancelImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	ff := &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary: f.Network.NodeBinary,
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
			{Entity: 1},
			{Entity: 1},
			{Entity: 1},
		},
		Seeds: []oasis.SeedFixture{{}},
	}

	ff.Network.SetMockEpoch()
	ff.Network.SetInsecureBeacon()

	return ff, nil
}

func (sc *nodeUpgradeCancelImpl) Run(childEnv *env.Env) error {
	var err error

	if err = sc.Net.Start(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for network to come up")
	if err = sc.Net.Controller().WaitNodesRegistered(sc.ctx, len(sc.Net.Validators())); err != nil {
		return err
	}
	if err = sc.nextEpoch(); err != nil {
		return err
	}

	val := sc.Net.Validators()[1] // the network controller is on the first one

	// Submit the descriptor. It's entirely valid, including the handler, so
	// the node should normally shut down when it reaches the epoch.
	sc.Logger.Info("submitting upgrade descriptor")

	descriptor := baseDescriptor
	descriptor.Handler = upgradeHandler
	descriptor.Epoch = 3

	filePath := path.Join(sc.Net.BasePath(), "upgrade-descriptor.json")
	desc, err := json.Marshal(descriptor)
	if err != nil {
		return fmt.Errorf("json.Marshal(descriptor): %w", err)
	}
	if err = ioutil.WriteFile(filePath, desc, 0o644); err != nil { //nolint: gosec
		return fmt.Errorf("can't write descriptor to network directory: %w", err)
	}

	submitArgs := []string{
		"control", "upgrade-binary",
		"--log.level", "debug",
		"--wait",
		"--address", "unix:" + val.SocketPath(),
		filePath,
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-upgrade", sc.Net.Config().NodeBinary, submitArgs); err != nil {
		return fmt.Errorf("error submitting upgrade descriptor to node: %w", err)
	}

	if err = sc.nextEpoch(); err != nil {
		return err
	}

	// Now cancel the upgrade.
	cancelArgs := []string{
		"control", "cancel-upgrade",
		"--log.level", "debug",
		"--wait",
		"--address", "unix:" + val.SocketPath(),
		filePath,
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-upgrade", sc.Net.Config().NodeBinary, cancelArgs); err != nil {
		return fmt.Errorf("error canceling upgrade: %w", err)
	}

	if err = sc.nextEpoch(); err != nil {
		return err
	}
	if err = sc.nextEpoch(); err != nil {
		return err
	}
	// This brings us to epoch 4. If the node failed to cancel the upgrade, it'll be dead by now.

	return sc.finishWithoutChild()
}
