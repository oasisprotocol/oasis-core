package runtime

import (
	"context"
	"fmt"

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
		runtimeImpl: *newRuntimeImpl("node-shutdown", nil),
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

	// Make sure one of the compute nodes can terminate early.
	f.ComputeWorkers[0].AllowEarlyTermination = true
	return f, nil
}

func (sc *nodeShutdownImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	var err error

	if err = sc.Net.Start(); err != nil {
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

	// Try restarting it; it should shutdown by itself soon after.
	if err = computeWorker.Restart(ctx); err != nil {
		return err
	}
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.Logger.Error("compute worker exited with error on second run",
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

	return nil
}
