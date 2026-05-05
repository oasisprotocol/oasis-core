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

	src := sc.Net.ComputeWorkers()[0]
	srcCtrl, err := oasis.NewController(src.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for the source node: %w", err)
	}

	// Use height - 3 so that blocks at h, h+1, h+2 all exist in the block store.
	blk, err := srcCtrl.Consensus.GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get latest consensus block: %w", err)
	}
	candidateHeight := blk.Height - 3
	rtState, err := srcCtrl.Roothash.GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: KeyValueRuntimeID,
		Height:    candidateHeight,
	})
	if err != nil {
		return fmt.Errorf("failed to get runtime state for height %d: %w", candidateHeight, err)
	}

	// Pick runtime state's LastBlockHeight as the consensus checkpoint height else
	// runtime light history indexer might miss authoritative light block for the
	// corresponding runtime round.
	cpRound := rtState.LastBlock.Header.Round
	cpHeight := rtState.LastBlockHeight

	// Ensure runtime round is synced before stopping the node and creating a checkpoint for it.
	if err := srcCtrl.WaitRuntimeRound(ctx, KeyValueRuntimeID, cpRound); err != nil {
		return fmt.Errorf("waiting runtime round %d: %w", cpRound, err)
	}

	// Stop compute worker 0 (source node).
	if err := src.StopGracefully(); err != nil {
		return fmt.Errorf("failed to stop source compute worker: %w", err)
	}

	// Create checkpoints from the source node's data.
	cpDir := filepath.Join(childEnv.Dir(), "checkpoint")

	sc.Logger.Info("creating checkpoints",
		"height", cpHeight,
		"round", cpRound,
		"runtime_id", KeyValueRuntimeID,
	)

	args := []string{
		"storage", "checkpoint", "create",
		"--config", src.ConfigFile(),
		"--height", fmt.Sprintf("%d", cpHeight),
		"--runtime", KeyValueRuntimeID.Hex(),
		"--round", fmt.Sprintf("%d", cpRound),
		"--output-dir", cpDir,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err := cli.RunSubCommand(childEnv, sc.Logger, "checkpoint-create", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to create checkpoints: %w", err)
	}

	sc.Logger.Info("checkpoints created successfully")

	// Start the source compute worker again.
	if err := src.Start(); err != nil {
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

	targetCtrl, err := oasis.NewController(target.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for target node: %w", err)
	}

	// Ensure target node syncs to the tip of the chain from the imported checkpoints.
	sc.Logger.Info("waiting for target node to sync")
	if err := targetCtrl.WaitReady(ctx); err != nil {
		return fmt.Errorf("target node failed to sync: %w", err)
	}
	sc.Logger.Info("target node is ready")

	// Manually ensure that runtime state was synced up to the latest round as
	// WaitReady only guarantees consensus sync.
	latestBlk, err := sc.Net.ClientController().Roothash.GetLatestBlock(ctx, &roothash.RuntimeRequest{
		RuntimeID: KeyValueRuntimeID,
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest runtime block: %w", err)
	}
	latestRound := latestBlk.Header.Round
	sc.Logger.Info("waiting the target node to have runtime state synced")
	if err := targetCtrl.WaitRuntimeRound(ctx, KeyValueRuntimeID, latestRound); err != nil {
		return fmt.Errorf("waiting synced runtime round %d: %w", latestRound, err)
	}
	sc.Logger.Info("target node has runtime state synced")

	// Ensure target synced from the imported checkpoint and not from the genesis.
	status, err := targetCtrl.NodeController.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get target node status: %w", err)
	}
	if lastRetainedHeight := status.Consensus.LastRetainedHeight; lastRetainedHeight != cpHeight {
		sc.Logger.Info("last retained height is not equal to the imported checkpoint height",
			"cp_height", cpHeight,
			"last_retained_height", lastRetainedHeight)
		return fmt.Errorf("failed to ensure consensus synced from the imported checkpoint")
	}
	// No need to assert target node didn't sync runtime state from the genesis,
	// since runtime genesis sync cannot succeed with a missing runtime light history
	// (the case when consensus is synced using an imported checkpoint, asserted above).

	return nil
}
