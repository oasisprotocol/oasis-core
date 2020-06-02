package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// NodeShutdown is the keymanager restart scenario.
	NodeShutdown scenario.Scenario = newNodeShutdownImpl()
)

type nodeShutdownImpl struct {
	runtimeImpl
}

func newNodeShutdownImpl() scenario.Scenario {
	sc := &nodeShutdownImpl{
		runtimeImpl: *newRuntimeImpl("node-shutdown", "", nil),
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
	var err error

	if err = sc.net.Start(); err != nil {
		return err
	}

	sc.logger.Info("requesting node shutdown")
	computeWorker := sc.runtimeImpl.net.ComputeWorkers()[0]

	// Wait for the node to be ready since we didn't wait for any clients.
	nodeCtrl, err := oasis.NewController(computeWorker.SocketPath())
	if err != nil {
		return err
	}
	if err = nodeCtrl.WaitSync(context.Background()); err != nil {
		return err
	}

	args := []string{
		"control", "shutdown",
		"--log.level", "debug",
		"--address", "unix:" + computeWorker.SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "control-shutdown", sc.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/node_shutdown: send request failed: %w", err)
	}

	// Wait for the node to exit.
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.logger.Error("compute worker exited with error",
			"err", err,
		)
		return err
	}

	// Try restarting it; it should shutdown by itself soon after.
	if err = computeWorker.Restart(); err != nil {
		return err
	}
	err = <-computeWorker.Exit()
	if err != env.ErrEarlyTerm {
		sc.logger.Error("compute worker exited with error on second run",
			"err", err,
		)
		return err
	}

	return nil
}
