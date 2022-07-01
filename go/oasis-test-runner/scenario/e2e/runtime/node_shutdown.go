package runtime

import (
	"context"
	"fmt"
	"time"

	tlsCert "github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/worker/common/api"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// NodeShutdown is the keymanager restart scenario.
var NodeShutdown scenario.Scenario = newNodeShutdownImpl()

type nodeShutdownImpl struct {
	runtimeImpl
}

func newNodeShutdownImpl() scenario.Scenario {
	sc := &nodeShutdownImpl{
		runtimeImpl: *newRuntimeImpl("node-shutdown", BasicKVTestClient),
	}
	return sc
}

func (sc *nodeShutdownImpl) Clone() scenario.Scenario {
	return &nodeShutdownImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *nodeShutdownImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Make sure the tested nodes can terminate early.
	f.ComputeWorkers[0].AllowEarlyTermination = true
	f.ComputeWorkers[1].AllowEarlyTermination = true
	// Disable cert rotation, as we will try to register with duplicate keys.
	f.ComputeWorkers[1].DisableCertRotation = true
	f.ComputeWorkers[2].DisableCertRotation = true

	return f, nil
}

func (sc *nodeShutdownImpl) Run(childEnv *env.Env) error { //nolint: gocyclo
	ctx := context.Background()
	var err error

	if err = sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for the node to become ready")
	computeWorker := sc.Net.ComputeWorkers()[0]

	// Wait for the node to be ready since we didn't wait for any clients.
	nodeCtrl, err := oasis.NewController(computeWorker.SocketPath())
	if err != nil {
		return err
	}
	if err = nodeCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Make sure that the GetStatus endpoint returns sensible values.
	status, err := nodeCtrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for node: %w", err)
	}
	if status.Consensus.Status != consensusAPI.StatusStateReady {
		return fmt.Errorf("node consensus status should be '%s', got: '%s'", consensusAPI.StatusStateReady, status.Consensus.Status)
	}
	if status.Runtimes[runtimeID].Committee == nil {
		return fmt.Errorf("node committee status missing")
	}
	if st := status.Runtimes[runtimeID].Committee.Status; st != api.StatusStateReady {
		return fmt.Errorf("node compute worker status should be '%s', got: '%s'", api.StatusStateReady, st)
	}
	if status.Registration.Descriptor == nil {
		return fmt.Errorf("node has not registered")
	}

	sc.Logger.Info("requesting node shutdown")
	args := []string{
		"control", "shutdown",
		"--log.level", "debug",
		"--address", "unix:" + computeWorker.SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-shutdown", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/node_shutdown: send request failed: %w", err)
	}

	// Wait for the node to exit.
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.Logger.Error("compute worker exited with error",
			"err", err,
		)
		return err
	}

	// Get the client node to shutdown as well, to make sure the code path works in corner cases too.
	clientNode := sc.Net.Clients()[0]
	clientCtrl, err := oasis.NewController(clientNode.SocketPath())
	if err != nil {
		return err
	}
	if err = clientCtrl.WaitReady(ctx); err != nil {
		return err
	}

	sc.Logger.Info("requesting client node shutdown")
	args = []string{
		"control", "shutdown",
		"--log.level", "debug",
		"--address", "unix:" + clientNode.SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-shutdown", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/node_shutdown: send request to client node failed: %w", err)
	}

	// Wait for the node to exit.
	err = <-clientNode.Exit()
	if err != env.ErrEarlyTerm {
		sc.Logger.Error("client node exited with error",
			"err", err,
		)
		return err
	}

	// Test request shutdown on a node that fails registration.
	// Stop the node and update its setup to ensure registration failing.
	computeWorker = sc.Net.ComputeWorkers()[1]
	if err = computeWorker.Stop(); err != nil {
		sc.Logger.Error("stopping compute worker 1",
			"err", err,
		)
		return err
	}

	// NOTE: this is a bit hacky, but we need an invalid node configuration where a node will try to register,
	// but the transaction needs to fail. Therefore it's not enough to just use an invalid entity or something alike
	// in which case the node will not even try to register. In real networks the most common error would likely be
	// an unroutable ip address, but that is allowed in e2e tests.
	// Use duplicate TLS keys to ensure registration transaction will always fail.
	cert, err := tlsCert.LoadFromKey(sc.Net.ComputeWorkers()[2].DataDir()+"/tls_identity.pem", identity.CommonName)
	if err != nil {
		return err
	}
	if err = tlsCert.Save(computeWorker.DataDir()+"/tls_identity_cert.pem", computeWorker.DataDir()+"/tls_identity.pem", cert); err != nil {
		return err
	}
	if err = computeWorker.Start(); err != nil {
		sc.Logger.Error("starting compute worker 1",
			"err", err,
		)
		return err
	}

	// The compute worker will never report as ready, so instead wait for it to start processing blocks.
	var blockCh <-chan *consensusAPI.Block
	var blockSub pubsub.ClosableSubscription
	ctrl, err := oasis.NewController(computeWorker.SocketPath())
	if err != nil {
		return err
	}
	blockCh, blockSub, err = ctrl.Consensus.WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer blockSub.Close()

	sc.Logger.Info("waiting for some blocks")
	var wait uint
	for {
		if wait > 5 {
			break
		}
		select {
		case <-blockCh:
			wait++
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timed out waiting for blocks")
		}
	}

	// Ensure compute worker failed to register.
	status, err = ctrl.GetStatus(ctx)
	if err != nil {
		return err
	}
	if status.Consensus.Status != consensusAPI.StatusStateReady {
		return fmt.Errorf("node consensus status should be '%s', got: '%s'", consensusAPI.StatusStateReady, status.Consensus.Status)
	}
	if status.Registration.NodeStatus != nil {
		return fmt.Errorf("node should not be registered")
	}

	// Test request shutdown.
	sc.Logger.Info("requesting node shutdown")
	args = []string{
		"control", "shutdown",
		"--log.level", "debug",
		"--address", "unix:" + computeWorker.SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "control-shutdown", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/node_shutdown: send request failed: %w", err)
	}

	// Wait for the node to exit.
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.Logger.Error("compute worker exited with error",
			"err", err,
		)
		return err
	}
	return nil
}
