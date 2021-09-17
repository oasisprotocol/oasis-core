package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"sync"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
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

func (n *noOpUpgradeChecker) PreUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	return nil
}

func (n *noOpUpgradeChecker) PostUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	return nil
}

type upgrade202108Checker struct{}

func (n *upgrade202108Checker) PreUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	return nil
}

func (n *upgrade202108Checker) PostUpgradeFn(ctx context.Context, ctrl *oasis.Controller) error {
	// Check updated staking parameters.
	stakeParams, err := ctrl.Staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get staking consensus parameters: %w", err)
	}
	if stakeParams.MaxAllowances != 16 {
		return fmt.Errorf("max allowances not updated")
	}
	if stakeParams.GasCosts[stakingAPI.GasOpAmendCommissionSchedule] != 1000 ||
		stakeParams.GasCosts[stakingAPI.GasOpAllow] != 1000 ||
		stakeParams.GasCosts[stakingAPI.GasOpWithdraw] != 1000 {
		return fmt.Errorf("staking gas costs not updated")
	}

	// Check updated governance parameters.
	govParams, err := ctrl.Governance.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get governance consensus parameters: %w", err)
	}
	if govParams.GasCosts[governanceAPI.GasOpCastVote] != 1000 ||
		govParams.GasCosts[governanceAPI.GasOpSubmitProposal] != 1000 {
		return fmt.Errorf("governance gas costs not updated")
	}

	// Check updated roothash parameters.
	roothashParams, err := ctrl.Roothash.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get roothash consensus parameters: %w", err)
	}
	if roothashParams.GasCosts[roothashAPI.GasOpProposerTimeout] != 5000 ||
		roothashParams.GasCosts[roothashAPI.GasOpEvidence] != 5000 {
		return fmt.Errorf("roothash gas costs not updated")
	}

	// Check updated scheduler parameters.
	schedParams, err := ctrl.Consensus.Scheduler().ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("can't get scheduler consensus parameters: %w", err)
	}
	if schedParams.MaxValidators != 110 {
		return fmt.Errorf("max validators not updated")
	}

	return nil
}

var (
	// NodeUpgradeDummy is the node upgrade dummy scenario.
	NodeUpgradeDummy scenario.Scenario = newNodeUpgradeImpl(migrations.DummyUpgradeHandler, &dummyUpgradeChecker{})
	// NodeUpgradeMaxAllowances is the node upgrade max allowances scenario.
	NodeUpgradeMaxAllowances scenario.Scenario = newNodeUpgradeImpl(migrations.ConsensusMaxAllowances16Handler, &noOpUpgradeChecker{})
	// NodeUpgradeConsensus202108 is the node consensus upgrade 202108 scenario.
	NodeUpgradeConsensus202108 scenario.Scenario = newNodeUpgradeImpl(migrations.ConsensusParamsUpdate202108, &upgrade202108Checker{})

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
	E2E

	validator  *oasis.Validator
	controller *oasis.Controller

	nodeCh <-chan *registry.NodeEvent

	ctx          context.Context
	currentEpoch beacon.EpochTime

	handlerName    upgrade.HandlerName
	upgradeChecker upgradeChecker
}

func (sc *nodeUpgradeImpl) writeDescriptor(name string, content []byte) (string, error) {
	filePath := path.Join(sc.Net.BasePath(), "upgrade-"+name+".json")
	if err := ioutil.WriteFile(filePath, content, 0o644); err != nil { //nolint: gosec
		sc.Logger.Error("can't write descriptor to network directory",
			"err", err,
			"name", name,
		)
		return "", err
	}
	return filePath, nil
}

func (sc *nodeUpgradeImpl) nextEpoch() error {
	sc.currentEpoch++
	if err := sc.Net.Controller().SetEpoch(sc.ctx, sc.currentEpoch); err != nil {
		// Errors can happen because an upgrade happens exactly during an epoch transition. So
		// make sure to ignore them.
		sc.Logger.Warn("failed to set epoch",
			"epoch", sc.currentEpoch,
			"err", err,
		)
	}
	return nil
}

func (sc *nodeUpgradeImpl) restart(wait bool) error {
	sc.Logger.Debug("restarting validator")
	if err := sc.validator.Restart(sc.ctx); err != nil {
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

func newNodeUpgradeImpl(handlerName upgrade.HandlerName, upgradeChecker upgradeChecker) scenario.Scenario {
	sc := &nodeUpgradeImpl{
		E2E:            *NewE2E("node-upgrade-" + string(handlerName)),
		ctx:            context.Background(),
		handlerName:    handlerName,
		upgradeChecker: upgradeChecker,
	}
	return sc
}

func (sc *nodeUpgradeImpl) Clone() scenario.Scenario {
	return &nodeUpgradeImpl{
		E2E:            sc.E2E.Clone(),
		ctx:            context.Background(),
		handlerName:    sc.handlerName,
		upgradeChecker: sc.upgradeChecker,
	}
}

func (sc *nodeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
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

func (sc *nodeUpgradeImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	var err error
	var descPath string

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

	var nodeSub pubsub.ClosableSubscription
	sc.nodeCh, nodeSub, err = sc.Net.Controller().Registry.WatchNodes(sc.ctx)
	if err != nil {
		return fmt.Errorf("can't subscribe to registry node events: %w", err)
	}
	defer nodeSub.Close()

	sc.validator = sc.Net.Validators()[1] // the network controller is on the first one
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

	// Run pre-upgrade checker.
	if err = sc.upgradeChecker.PreUpgradeFn(sc.ctx, sc.Net.Controller()); err != nil {
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
	svcStore, err := store.GetServiceStore("upgrade")
	if err != nil {
		store.Close()
		return fmt.Errorf("can't open upgraded node's upgrade module storage: %w", err)
	}
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
	if err = sc.restart(true); err != nil {
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
	if err = sc.nextEpoch(); err != nil {
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
			if restartError := val.Restart(sc.ctx); err != nil {
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
	if err = sc.Net.Controller().WaitNodesRegistered(sc.ctx, len(sc.Net.Validators())); err != nil {
		return err
	}
	sc.Logger.Info("final epoch advance")
	if err = sc.nextEpoch(); err != nil {
		return err
	}

	// Run post-upgrade checker.
	if err = sc.upgradeChecker.PostUpgradeFn(sc.ctx, sc.Net.Controller()); err != nil {
		return err
	}

	return sc.finishWithoutChild()
}
