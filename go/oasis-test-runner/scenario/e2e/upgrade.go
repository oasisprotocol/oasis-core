package e2e

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"sync"
	"time"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/persistent"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	epoch "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/upgrade/migrations"
)

var (
	// NodeUpgrade is the node upgrade scenario.
	NodeUpgrade scenario.Scenario = newNodeUpgradeImpl()

	malformedDescriptor = []byte(`{
		"name": "nifty upgrade",
		"epoch": 1,
		"method": "nifty",
		"identifier": "this is a hash. i repeat. this is a hash, not a string."
	}`)

	// Warning: this string contains printf conversions, it's NOT directly usable as a descriptor.
	nonexistentDescriptorTemplate = `{
		"name": "nonexistent-handler",
		"epoch": %d,
		"method": "internal",
		"identifier": "0000000000000000000000000000000000000000000000000000000000000000"
	}`

	// Warning: this string contains printf conversions, it's NOT directly usable as a descriptor.
	validDescriptorTemplate = `{
		"name": "%v",
		"epoch": %d,
		"method": "internal",
		"identifier": "%v"
	}`
)

type nodeUpgradeImpl struct {
	basicImpl

	validator  *oasis.Validator
	controller *oasis.Controller

	nodeCh <-chan *registry.NodeEvent

	ctx          context.Context
	currentEpoch epoch.EpochTime
}

func (sc *nodeUpgradeImpl) writeDescriptor(name string, content []byte) (string, error) {
	filePath := path.Join(sc.net.BasePath(), "upgrade-"+name+".json")
	if err := ioutil.WriteFile(filePath, content, 0644); err != nil {
		sc.logger.Error("can't write descriptor to network directory",
			"err", err,
			"name", name,
		)
		return "", err
	}
	return filePath, nil
}

func (sc *nodeUpgradeImpl) nextEpoch() error {
	sc.currentEpoch++
	if err := sc.net.Controller().SetEpoch(sc.ctx, sc.currentEpoch); err != nil {
		return fmt.Errorf("failed to set epoch to %d: %w", sc.currentEpoch, err)
	}
	return nil
}

func (sc *nodeUpgradeImpl) restart(wait bool) error {
	sc.logger.Debug("restarting validator")
	if err := sc.validator.Restart(); err != nil {
		return fmt.Errorf("can't restart validator: %w", err)
	}

	if !wait {
		return nil
	}

	for {
		select {
		case ev := <-sc.nodeCh:
			if ev.IsRegistration && ev.Node.ID.Equal(sc.validator.NodeID) {
				// Nothing else is restarted, so no need to check for specifics here.
				_ = sc.controller.WaitSync(sc.ctx)
				return nil
			}
		case <-time.After(60 * time.Second):
			return fmt.Errorf("timed out waiting for validator to re-register")
		}
	}
}

func newNodeUpgradeImpl() scenario.Scenario {
	sc := &nodeUpgradeImpl{
		basicImpl: *newBasicImpl("node-upgrade", "", nil),
		ctx:       context.Background(),
	}
	return sc
}

func (sc *nodeUpgradeImpl) Name() string {
	return "node-upgrade"
}

func (sc *nodeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
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
			NodeBinary:          viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary: viper.GetString(cfgRuntimeLoader),
			EpochtimeMock:       true,
			DefaultLogWatcherHandlerFactories: []log.WatcherHandlerFactory{
				oasis.LogAssertUpgradeStartup(),
				oasis.LogAssertUpgradeConsensus(),
			},
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1, AllowErrorTermination: true},
			oasis.ValidatorFixture{Entity: 1, AllowErrorTermination: true},
			oasis.ValidatorFixture{Entity: 1, AllowErrorTermination: true},
			oasis.ValidatorFixture{Entity: 1, AllowErrorTermination: true},
		},
	}, nil
}

func (sc *nodeUpgradeImpl) Run(childEnv *env.Env) error {
	var err error
	var descPath string

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

	var nodeSub pubsub.ClosableSubscription
	sc.nodeCh, nodeSub, err = sc.net.Controller().Registry.WatchNodes(sc.ctx)
	if err != nil {
		return fmt.Errorf("can't subscribe to registry node events: %w", err)
	}
	defer nodeSub.Close()

	sc.validator = sc.net.Validators()[1] // the network controller is on the first one
	submitArgs := []string{
		"control", "upgrade-binary",
		"--log.level", "debug",
		"--wait",
		"--address", "unix:" + sc.validator.SocketPath(),
	}

	// Wait for the node to be ready since we didn't wait for any clients.
	sc.controller, err = oasis.NewController(sc.validator.SocketPath())
	if err != nil {
		return err
	}
	if err = sc.controller.WaitSync(sc.ctx); err != nil {
		return err
	}

	// Try submitting an invalid update descriptor.
	// This should return immediately and the node should still be running.
	sc.logger.Info("submitting invalid upgrade descriptor")
	if descPath, err = sc.writeDescriptor("malformed", malformedDescriptor); err != nil {
		return err
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "control-upgrade", sc.net.Config().NodeBinary, append(submitArgs, descPath)); err == nil {
		sc.logger.Error("submitting malformed descriptor didn't result in an error. that's an error.")
		return errors.New("there should be errors with malformed descriptor")
	}

	// Try submitting a well formed descriptor but with an off hash, so no handlers are run.
	// The node should exit immediately.
	sc.logger.Info("submitting descriptor with nonexistent upgrade handler")
	nonexistentDescriptor := fmt.Sprintf(nonexistentDescriptorTemplate, sc.currentEpoch+1)
	if descPath, err = sc.writeDescriptor("nonexistent", []byte(nonexistentDescriptor)); err != nil {
		return err
	}

	if err = cli.RunSubCommand(childEnv, sc.logger, "control-upgrade", sc.net.Config().NodeBinary, append(submitArgs, descPath)); err != nil {
		return fmt.Errorf("error submitting descriptor with nonexistent handler to node: %w", err)
	}

	if err = sc.nextEpoch(); err != nil {
		return err
	}
	<-sc.validator.Exit()
	// The node will exit uncleanly due to the interesting consensus implementation.
	// We don't need the error here.

	// Try restarting the node. It should exit immediately now; on paper it can't handle the upgrade
	// described in the descriptor.
	if err = sc.restart(false); err != nil {
		return err
	}
	<-sc.validator.Exit()

	// Remove the stored descriptor so we can restart and submit a proper one.
	sc.logger.Info("clearing stored upgrade descriptor")
	store, err := persistent.NewCommonStore(sc.validator.DataDir())
	if err != nil {
		return fmt.Errorf("can't open upgraded node's persistent store: %w", err)
	}
	svcStore, err := store.GetServiceStore("upgrade")
	if err != nil {
		store.Close()
		return fmt.Errorf("can't open upgraded node's upgrade module storage: %w", err)
	}
	if err = svcStore.Delete([]byte("descriptor")); err != nil {
		svcStore.Close()
		store.Close()
		return fmt.Errorf("can't delete descripotor from upgraded node's persistent store: %w", err)
	}
	svcStore.Close()
	store.Close()

	// Generate a valid upgrade descriptor; this should exercise the test handlers in the node.
	var nodeHash hash.Hash
	nodeText, err := ioutil.ReadFile(sc.net.Validators()[0].BinaryPath())
	if err != nil {
		return fmt.Errorf("can't read node binary for hashing: %w", err)
	}
	nodeHash.FromBytes(nodeText)

	validDescriptor := fmt.Sprintf(validDescriptorTemplate, migrations.DummyUpgradeName, sc.currentEpoch+1, nodeHash.String())

	if descPath, err = sc.writeDescriptor("valid", []byte(validDescriptor)); err != nil {
		return err
	}

	// Restart the node again, so we have the full set of validators.
	if err = sc.restart(true); err != nil {
		return err
	}

	// Now submit the valid descriptor to all of the validators.
	sc.logger.Info("submitting valid upgrade descriptor to all validators")
	for i, val := range sc.net.Validators() {
		submitArgs[len(submitArgs)-1] = "unix:" + val.SocketPath()
		if err = cli.RunSubCommand(childEnv, sc.logger, "control-upgrade", sc.net.Config().NodeBinary, append(submitArgs, descPath)); err != nil {
			return fmt.Errorf("failed to submit upgrade descriptor to validator %d: %w", i, err)
		}
	}
	if err = sc.nextEpoch(); err != nil {
		return err
	}

	sc.logger.Info("restarting network")
	errCh := make(chan error, len(sc.net.Validators()))
	var group sync.WaitGroup
	for i, val := range sc.net.Validators() {
		group.Add(1)
		go func(i int, val *oasis.Validator) {
			defer group.Done()
			sc.logger.Debug("waiting for validator to exit", "num", i)
			<-val.Exit()
			sc.logger.Debug("restarting validator", "num", i)
			if restartError := val.Restart(); err != nil {
				errCh <- restartError
			}
		}(i, val)
	}

	group.Wait()
	select {
	case err = <-errCh:
		return fmt.Errorf("can't restart upgraded validator for upgrade test: %w", err)
	default:
	}

	sc.logger.Info("waiting for network to come back up")
	if err = sc.net.Controller().WaitNodesRegistered(sc.ctx, len(sc.net.Validators())); err != nil {
		return err
	}
	sc.logger.Info("final epoch advance")
	if err = sc.nextEpoch(); err != nil {
		return err
	}

	// Check the entity set during consensus upgrade.
	idQuery := &registry.IDQuery{
		Height: consensus.HeightLatest,
		ID:     migrations.TestEntity.ID,
	}
	_, err = sc.net.Controller().Registry.GetEntity(sc.ctx, idQuery)
	if err != nil {
		return fmt.Errorf("can't get registered test entity: %w", err)
	}

	return sc.finishWithoutChild()
}
