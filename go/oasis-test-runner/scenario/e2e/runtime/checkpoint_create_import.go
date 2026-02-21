package runtime

import (
	"context"
	"fmt"
	"path/filepath"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// CheckpointCreateImport is the checkpoint create/import e2e scenario.
var CheckpointCreateImport scenario.Scenario = newCheckpointCreateImportImpl()

type checkpointCreateImportImpl struct {
	Scenario
}

func newCheckpointCreateImportImpl() scenario.Scenario {
	return &checkpointCreateImportImpl{
		Scenario: *NewScenario(
			"checkpoint-create-import",
			NewTestClient().WithScenario(SimpleScenario),
		),
	}
}

func (sc *checkpointCreateImportImpl) Clone() scenario.Scenario {
	return &checkpointCreateImportImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *checkpointCreateImportImpl) Fixture() (*oasis.NetworkFixture, error) {
	return sc.Scenario.Fixture()
}

func (sc *checkpointCreateImportImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Start the network and run the test client to populate state.
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	if err := sc.WaitTestClient(); err != nil {
		return err
	}

	// Record the current consensus height and runtime round.
	blk, err := sc.Net.Controller().Consensus.GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get latest consensus block: %w", err)
	}
	// Use height - 3 so that blocks at h, h+1, h+2 all exist in the block store.
	height := blk.Height - 3

	rtBlk, err := sc.Net.ClientController().Roothash.GetLatestBlock(ctx, &roothash.RuntimeRequest{
		RuntimeID: KeyValueRuntimeID,
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest runtime block: %w", err)
	}
	round := rtBlk.Header.Round

	sc.Logger.Info("creating checkpoints",
		"height", height,
		"round", round,
		"runtime_id", KeyValueRuntimeID,
	)

	cpDir := filepath.Join(childEnv.Dir(), "checkpoint")

	// Stop compute worker 0 (source node).
	source := sc.Net.ComputeWorkers()[0]
	if err := source.StopGracefully(); err != nil {
		return fmt.Errorf("failed to stop source compute worker: %w", err)
	}

	// Create checkpoints from the source node's data.
	args := []string{
		"storage", "checkpoint", "create",
		"--config", source.ConfigFile(),
		"--height", fmt.Sprintf("%d", height),
		"--runtime", KeyValueRuntimeID.Hex(),
		"--round", fmt.Sprintf("%d", round),
		"--output-dir", cpDir,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err := cli.RunSubCommand(childEnv, sc.Logger, "checkpoint-create", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to create checkpoints: %w", err)
	}

	sc.Logger.Info("checkpoints created successfully")

	// Start the source compute worker again.
	if err := source.Start(); err != nil {
		return fmt.Errorf("failed to restart source compute worker: %w", err)
	}

	// Stop compute worker 2 (target node).
	target := sc.Net.ComputeWorkers()[2]
	if err := target.StopGracefully(); err != nil {
		return fmt.Errorf("failed to stop target compute worker: %w", err)
	}

	// Reset the target node's state completely. Ideally we would use NoAutoStart,
	// however if we do so no config is created until the node is started and import
	// command therefore fails.
	sc.Logger.Info("resetting target node state")
	cliHelpers := cli.New(childEnv, sc.Net, sc.Logger)
	if err := cliHelpers.UnsafeReset(target.DataDir(), false, false, true); err != nil {
		return fmt.Errorf("failed to reset target node state: %w", err)
	}

	// Import checkpoints into the target node.
	sc.Logger.Info("importing checkpoints into target node")
	args = []string{
		"storage", "checkpoint", "import",
		"--config", target.ConfigFile(),
		"--input-dir", cpDir,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err := cli.RunSubCommand(childEnv, sc.Logger, "checkpoint-import", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to import checkpoints: %w", err)
	}

	sc.Logger.Info("checkpoints imported, starting target node")

	// Start the target node.
	if err := target.Start(); err != nil {
		return fmt.Errorf("failed to start target node: %w", err)
	}

	// Wait for the target node to sync.
	sc.Logger.Info("waiting for target node to sync")
	ctrl, err := oasis.NewController(target.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for target node: %w", err)
	}
	if err := ctrl.WaitReady(ctx); err != nil {
		return fmt.Errorf("target node failed to sync: %w", err)
	}

	return nil
}
