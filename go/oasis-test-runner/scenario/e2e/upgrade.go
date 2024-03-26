package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

type upgradeChecker interface {
	PreUpgradeFn(context.Context, *oasis.Controller) error
	PostUpgradeFn(context.Context, *oasis.Controller) error
}

type dummyUpgradeChecker struct {
	preUpgradeParams *consensus.Parameters
}

func (d *dummyUpgradeChecker) PreUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	initialParams, err := ctrl.Consensus.GetParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get consensus parameters: %w", err)
	}
	d.preUpgradeParams = initialParams
	return nil
}

func (d *dummyUpgradeChecker) PostUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Check the entity set during consensus upgrade.
	idQuery := &registry.IDQuery{
		Height: consensus.HeightLatest,
		ID:     migrations.TestEntity.ID,
	}
	_, err := ctrl.Registry.GetEntity(ctx, idQuery)
	if err != nil {
		return fmt.Errorf("can't get registered test entity: %w", err)
	}

	// Check updated consensus parameters.
	newParams, err := ctrl.Consensus.GetParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get consensus parameters: %w", err)
	}
	if newParams.Parameters.MaxTxSize != d.preUpgradeParams.Parameters.MaxTxSize+1 {
		return fmt.Errorf("consensus parameter MaxTxSize not updated correctly (expected: %d actual: %d)",
			d.preUpgradeParams.Parameters.MaxTxSize+1,
			newParams.Parameters.MaxTxSize,
		)
	}
	return nil
}

type noOpUpgradeChecker struct{}

func (n *noOpUpgradeChecker) PreUpgradeFn(context.Context, *oasis.Controller) error {
	return nil
}

func (n *noOpUpgradeChecker) PostUpgradeFn(context.Context, *oasis.Controller) error {
	return nil
}

type upgrade240Checker struct{}

func (c *upgrade240Checker) PreUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Check registry parameters.
	registryParams, err := ctrl.Registry.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get registry consensus parameters: %w", err)
	}
	if registryParams.EnableKeyManagerCHURP {
		return fmt.Errorf("key manager CHURP extension is enabled")
	}

	// Check CHURP parameters.
	_, err = ctrl.Keymanager.Churp().ConsensusParameters(ctx, consensus.HeightLatest)
	if err == nil {
		return fmt.Errorf("key manager CHURP consensus parameters shouldn't be set: %w", err)
	}

	return nil
}

func (c *upgrade240Checker) PostUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Check updated consensus parameters.
	consParams, err := ctrl.Consensus.GetParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get consensus parameters: %w", err)
	}
	if expectedMaxTxSize := 128 * 1024; consParams.Parameters.MaxTxSize != uint64(expectedMaxTxSize) {
		return fmt.Errorf("consensus parameter MaxTxSize not updated correctly (expected: %d actual: %d)",
			expectedMaxTxSize,
			consParams.Parameters.MaxTxSize,
		)
	}
	if expectedMaxBlockSize := 4 * 1024 * 1024; consParams.Parameters.MaxBlockSize != uint64(expectedMaxBlockSize) {
		return fmt.Errorf("consensus parameter MaxBlockSize not updated correctly (expected: %d actual: %d)",
			expectedMaxBlockSize,
			consParams.Parameters.MaxBlockSize,
		)
	}

	// Check updated registry parameters.
	registryParams, err := ctrl.Registry.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get registry consensus parameters: %w", err)
	}
	if !registryParams.EnableKeyManagerCHURP {
		return fmt.Errorf("key manager CHURP extension is disabled")
	}

	// Check updated CHURP parameters.
	churpParams, err := ctrl.Keymanager.Churp().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get key manager CHURP consensus parameters: %w", err)
	}
	if !reflect.DeepEqual(*churpParams, churp.DefaultConsensusParameters) {
		return fmt.Errorf("key manager CHURP consensus parameters are not default")
	}

	// Check updated governance parameters.
	govParams, err := ctrl.Governance.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get governance parameters: %w", err)
	}
	if expectedStakeThreshold := uint8(60); govParams.StakeThreshold != expectedStakeThreshold {
		return fmt.Errorf("governance stake threshold not updated correctly (expected: %d actual: %d)",
			expectedStakeThreshold,
			govParams.StakeThreshold,
		)
	}

	return nil
}

var (
	// NodeUpgradeDummy is the node upgrade dummy scenario.
	NodeUpgradeDummy scenario.Scenario = newNodeUpgradeImpl(migrations.DummyUpgradeHandler, &dummyUpgradeChecker{})
	// NodeUpgradeEmpty is the empty node upgrade scenario.
	NodeUpgradeEmpty scenario.Scenario = newNodeUpgradeImpl(migrations.EmptyHandler, &noOpUpgradeChecker{})
	// NodeUpgradeConsensus240 is the node upgrade scenario for migrating to consensus 24.0.
	NodeUpgradeConsensus240 scenario.Scenario = newNodeUpgradeImpl(migrations.Consensus240, &upgrade240Checker{})

	malformedDescriptor = []byte(`{
		"v": 1,
		"handler": "nifty upgrade",
		"target": "not a version",
		"epoch": 1,
	}`)

	baseDescriptor = upgrade.Descriptor{
		Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
		Handler:   "base",
		Target:    version.Versions,
		Epoch:     beacon.EpochTime(1),
	}
)

type nodeUpgradeImpl struct {
	Scenario

	validator  *oasis.Validator
	controller *oasis.Controller

	nodeCh <-chan *registry.NodeEvent

	currentEpoch beacon.EpochTime

	handlerName    upgrade.HandlerName
	upgradeChecker upgradeChecker
}

func (sc *nodeUpgradeImpl) writeDescriptor(name string, content []byte) (string, error) {
	filePath := path.Join(sc.Net.BasePath(), "upgrade-"+name+".json")
	if err := os.WriteFile(filePath, content, 0o644); err != nil { //nolint: gosec
		sc.Logger.Error("can't write descriptor to network directory",
			"err", err,
			"name", name,
		)
		return "", err
	}
	return filePath, nil
}

func (sc *nodeUpgradeImpl) nextEpoch(ctx context.Context) error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(ctx, sc.currentEpoch); err != nil {
		// Errors can happen because an upgrade happens exactly during an epoch transition. So
		// make sure to ignore them.
		sc.Logger.Warn("failed to set epoch",
			"epoch", sc.currentEpoch,
			"err", err,
		)
	}
	return nil
}

func (sc *nodeUpgradeImpl) restart(ctx context.Context, wait bool) error {
	sc.Logger.Debug("restarting validator")
	if err := sc.validator.Restart(ctx); err != nil {
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
				_ = sc.controller.WaitSync(ctx)
				return nil
			}
		case <-time.After(60 * time.Second):
			return fmt.Errorf("timed out waiting for validator to re-register")
		}
	}
}

func newNodeUpgradeImpl(handlerName upgrade.HandlerName, upgradeChecker upgradeChecker) scenario.Scenario {
	sc := &nodeUpgradeImpl{
		Scenario:       *NewScenario("node-upgrade-" + string(handlerName)),
		handlerName:    handlerName,
		upgradeChecker: upgradeChecker,
	}
	return sc
}

func (sc *nodeUpgradeImpl) Clone() scenario.Scenario {
	return &nodeUpgradeImpl{
		Scenario:       *sc.Scenario.Clone().(*Scenario),
		handlerName:    sc.handlerName,
		upgradeChecker: sc.upgradeChecker,
	}
}

func (sc *nodeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	ff := &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary: f.Network.NodeBinary,
			DefaultLogWatcherHandlerFactories: []log.WatcherHandlerFactory{
				oasis.LogAssertUpgradeStartup(),
				oasis.LogAssertUpgradeConsensus(),
			},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, AllowErrorTermination: true, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
			{Entity: 1, AllowErrorTermination: true},
			{Entity: 1, AllowErrorTermination: true},
			{Entity: 1, AllowErrorTermination: true},
		},
		Seeds: []oasis.SeedFixture{{}},
	}

	ff.Network.SetMockEpoch()
	ff.Network.SetInsecureBeacon()

	return ff, nil
}

func (sc *nodeUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error { // nolint: gocyclo
	var err error
	var descPath string

	if err = sc.Net.Start(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for network to come up")
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return err
	}
	if err = sc.nextEpoch(ctx); err != nil {
		return err
	}

	var nodeSub pubsub.ClosableSubscription
	sc.nodeCh, nodeSub, err = sc.Net.Controller().Registry.WatchNodes(ctx)
	if err != nil {
		return fmt.Errorf("can't subscribe to registry node events: %w", err)
	}
	defer nodeSub.Close()

	sc.validator = sc.Net.Validators()[1] // the network controller is on the first one
	submitArgs := []string{
		"control", "upgrade-binary",
		"--wait",
		"--address", "unix:" + sc.validator.SocketPath(),
	}

	// Wait for the node to be ready since we didn't wait for any clients.
	sc.controller, err = oasis.NewController(sc.validator.SocketPath())
	if err != nil {
		return err
	}
	if err = sc.controller.WaitSync(ctx); err != nil {
		return err
	}

	// Run pre-upgrade checker.
	if err = sc.upgradeChecker.PreUpgradeFn(ctx, sc.Net.Controller()); err != nil {
		return err
	}

	// Try submitting an invalid update descriptor.
	// This should return immediately and the node should still be running.
	sc.Logger.Info("submitting invalid upgrade descriptor")
	if descPath, err = sc.writeDescriptor("malformed", malformedDescriptor); err != nil {
		return err
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-upgrade", sc.Net.Config().NodeBinary, append(submitArgs, descPath)); err == nil {
		sc.Logger.Error("submitting malformed descriptor didn't result in an error. that's an error.")
		return errors.New("there should be errors with malformed descriptor")
	}

	// Try submitting a well formed descriptor but with an off hash, so no handlers are run.
	// The node should exit immediately.
	sc.Logger.Info("submitting descriptor with nonexistent upgrade handler")
	nonExistingDescriptor := baseDescriptor
	nonExistingDescriptor.Handler = "nonexistent"
	nonExistingDescriptor.Epoch = sc.currentEpoch + 1

	desc, err := json.Marshal(nonExistingDescriptor)
	if err != nil {
		return fmt.Errorf("json.Marshal(nonExistingDescriptor): %w", err)
	}
	if descPath, err = sc.writeDescriptor("nonexistent", desc); err != nil {
		return err
	}

	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-upgrade", sc.Net.Config().NodeBinary, append(submitArgs, descPath)); err != nil {
		return fmt.Errorf("error submitting descriptor with nonexistent handler to node: %w", err)
	}

	if err = sc.nextEpoch(ctx); err != nil {
		return err
	}
	<-sc.validator.Exit()
	// The node will exit uncleanly due to the interesting consensus implementation.
	// We don't need the error here.

	// Try restarting the node. It should exit immediately now; on paper it can't handle the upgrade
	// described in the descriptor.
	if err = sc.restart(ctx, false); err != nil {
		return err
	}
	<-sc.validator.Exit()

	// Verify that the node exported a genesis file before halting for upgrade.
	sc.Logger.Info("gathering exported genesis files")
	dumpGlobPath := filepath.Join(sc.validator.ExportsPath(), "genesis-*.json")
	globMatch, err := filepath.Glob(dumpGlobPath)
	if err != nil {
		return fmt.Errorf("glob failed: %s: %w", dumpGlobPath, err)
	}
	if len(globMatch) == 0 {
		return fmt.Errorf("no exported genesis files found in: %s", dumpGlobPath)
	}

	// Remove the stored descriptor so we can restart and submit a proper one.
	sc.Logger.Info("clearing stored upgrade descriptor")
	store, err := persistent.NewCommonStore(sc.validator.DataDir())
	if err != nil {
		return fmt.Errorf("can't open upgraded node's persistent store: %w", err)
	}
	svcStore := store.GetServiceStore("upgrade")
	if err = svcStore.Delete([]byte("descriptors")); err != nil {
		svcStore.Close()
		store.Close()
		return fmt.Errorf("can't delete descriptor from upgraded node's persistent store: %w", err)
	}
	svcStore.Close()
	store.Close()

	validDescriptor := baseDescriptor
	validDescriptor.Handler = sc.handlerName
	validDescriptor.Epoch = sc.currentEpoch + 1
	desc, err = json.Marshal(validDescriptor)
	if err != nil {
		return fmt.Errorf("json.Marshal(validDescriptor): %w", err)
	}
	if descPath, err = sc.writeDescriptor("valid", desc); err != nil {
		return err
	}

	// Restart the node again, so we have the full set of validators.
	if err = sc.restart(ctx, true); err != nil {
		return err
	}

	// Now submit the valid descriptor to all of the validators.
	sc.Logger.Info("submitting valid upgrade descriptor to all validators")
	for i, val := range sc.Net.Validators() {
		submitArgs[len(submitArgs)-1] = "unix:" + val.SocketPath()
		if err = cli.RunSubCommand(childEnv, sc.Logger, "control-upgrade", sc.Net.Config().NodeBinary, append(submitArgs, descPath)); err != nil {
			return fmt.Errorf("failed to submit upgrade descriptor to validator %d: %w", i, err)
		}
	}
	if err = sc.nextEpoch(ctx); err != nil {
		return err
	}

	sc.Logger.Info("restarting network")
	errCh := make(chan error, len(sc.Net.Validators()))
	var group sync.WaitGroup
	for i, val := range sc.Net.Validators() {
		group.Add(1)
		go func(i int, val *oasis.Validator) {
			defer group.Done()
			sc.Logger.Debug("waiting for validator to exit", "num", i)
			<-val.Exit()
			sc.Logger.Debug("restarting validator", "num", i)
			if restartError := val.Restart(ctx); err != nil {
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

	sc.Logger.Info("waiting for network to come back up")
	for _, n := range sc.Net.Validators() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}
	sc.Logger.Info("final epoch advance")
	if err = sc.nextEpoch(ctx); err != nil {
		return err
	}

	// Wait for some blocks after the upgrade to make sure we don't query too fast.
	_, err = sc.WaitBlocks(ctx, 2)
	if err != nil {
		return fmt.Errorf("failed to wait for blocks: %w", err)
	}

	// Run post-upgrade checker.
	if err = sc.upgradeChecker.PostUpgradeFn(ctx, sc.Net.Controller()); err != nil {
		return err
	}

	return sc.finishWithoutChild()
}
