package e2e

import (
	"context"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	epoch "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// NodeUpgradeCancel is the node upgrade scenario.
	NodeUpgradeCancel scenario.Scenario = newNodeUpgradeCancelImpl()

	// Warning: this string contains printf conversions, it's NOT directly usable as a descriptor.
	descriptorTemplate = `{
		"name": "__e2e-test-upgrade-cancel",
		"epoch": 3,
		"method": "internal",
		"identifier": "%v"
	}`
)

type nodeUpgradeCancelImpl struct {
	basicImpl

	ctx          context.Context
	currentEpoch epoch.EpochTime
}

func (sc *nodeUpgradeCancelImpl) nextEpoch() error {
	sc.currentEpoch++
	if err := sc.net.Controller().SetEpoch(sc.ctx, sc.currentEpoch); err != nil {
		return fmt.Errorf("failed to set epoch to %d: %w", sc.currentEpoch, err)
	}
	return nil
}

func newNodeUpgradeCancelImpl() scenario.Scenario {
	sc := &nodeUpgradeCancelImpl{
		basicImpl: *newBasicImpl("node-upgrade-cancel", "", nil),
		ctx:       context.Background(),
	}
	return sc
}

func (sc *nodeUpgradeCancelImpl) Name() string {
	return "node-upgrade-cancel"
}

func (sc *nodeUpgradeCancelImpl) Fixture() (*oasis.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &ias.FortanixTestMrSigner
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary:               viper.GetString(cfgRuntimeLoader),
			EpochtimeMock:                     true,
			DefaultLogWatcherHandlerFactories: DefaultBasicLogWatcherHandlerFactories,
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1},
			oasis.ValidatorFixture{Entity: 1},
			oasis.ValidatorFixture{Entity: 1},
			oasis.ValidatorFixture{Entity: 1},
		},
	}, nil
}

func (sc *nodeUpgradeCancelImpl) Run(childEnv *env.Env) error {
	var err error

	if err = sc.net.Start(); err != nil {
		return err
	}

	sc.logger.Info("waiting for network to come up")
	if err = sc.net.Controller().WaitNodesRegistered(sc.ctx, len(sc.net.Validators())); err != nil {
		return err
	}
	if err = sc.nextEpoch(); err != nil {
		return err
	}

	val := sc.net.Validators()[1] // the network controller is on the first one

	// Submit the descriptor. It's entirely valid, including the handler, so
	// the node should normally shut down when it reaches the epoch.
	sc.logger.Info("submitting upgrade descriptor")

	var nodeHash hash.Hash
	nodeText, err := ioutil.ReadFile(sc.net.Validators()[0].BinaryPath())
	if err != nil {
		return fmt.Errorf("can't read node binary for hashing: %w", err)
	}
	nodeHash.FromBytes(nodeText)

	descriptor := fmt.Sprintf(descriptorTemplate, nodeHash.String())

	filePath := path.Join(sc.net.BasePath(), "upgrade-descriptor.json")
	if err = ioutil.WriteFile(filePath, []byte(descriptor), 0644); err != nil {
		return fmt.Errorf("can't write descriptor to network directory: %w", err)
	}

	submitArgs := []string{
		"control", "upgrade-binary",
		"--log.level", "debug",
		"--wait",
		"--address", "unix:" + val.SocketPath(),
		filePath,
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "control-upgrade", sc.net.Config().NodeBinary, submitArgs); err != nil {
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
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "control-upgrade", sc.net.Config().NodeBinary, cancelArgs); err != nil {
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
