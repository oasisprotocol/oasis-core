package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	cmdStorage "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/storage"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	oasisCli "github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// OfflinePruning is the offline pruning e2e scenario.
var OfflinePruning scenario.Scenario = newOfflinePruningImpl()

type offlinePruningImpl struct {
	Scenario
}

func newOfflinePruningImpl() scenario.Scenario {
	return &offlinePruningImpl{
		Scenario: *NewScenario(
			"offline-pruning",
			NewTestClient().WithScenario(SimpleScenario),
		),
	}
}

func (sc *offlinePruningImpl) Clone() scenario.Scenario {
	return &offlinePruningImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *offlinePruningImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	client := oasis.ClientFixture{
		RuntimeProvisioner: f.Clients[0].RuntimeProvisioner,
		Runtimes:           []int{1},
	}
	f.Clients = append(f.Clients, client)

	return f, nil
}

func (sc *offlinePruningImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Start the network and run the test client to populate state.
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	if err := sc.WaitTestClient(); err != nil {
		return err
	}

	// Ensure client on which offline pruning and compaction will be done has successfully
	// synced at least twice the number of versions the pruner will keep.
	const offlinePruningNumKept uint64 = 5
	minSyncedConsensusHeight := offlinePruningNumKept * 2
	minSyncedRuntimeRound := offlinePruningNumKept * 2
	client := sc.Net.Clients()[1]
	clientCtrl, err := oasis.NewController(client.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for client node: %w", err)
	}
	defer clientCtrl.Close()
	if err := clientCtrl.WaitConsensusHeight(ctx, int64(minSyncedConsensusHeight)); err != nil {
		return err
	}
	if err := clientCtrl.WaitRuntimeRound(ctx, KeyValueRuntimeID, minSyncedRuntimeRound); err != nil {
		return err
	}

	if err := client.StopGracefully(); err != nil {
		return fmt.Errorf("failed to stop client node: %w", err)
	}

	beforePrune, err := sc.fetchStorageInspectStatus(childEnv, client.Node)
	if err != nil {
		return err
	}

	if err := sc.setPruningConfig(client.Node, offlinePruningNumKept); err != nil {
		return err
	}
	if err := sc.runOfflinePruning(childEnv, client.Node); err != nil {
		return err
	}
	if err := sc.runOfflineCompaction(childEnv, client.Node); err != nil {
		return err
	}

	afterPrune, err := sc.fetchStorageInspectStatus(childEnv, client.Node)
	if err != nil {
		return err
	}

	ensurePruned := func(want, got uint64) error {
		if want != got {
			return fmt.Errorf("want last retained version %d, got %d", want, got)
		}
		return nil
	}

	// The test assumes that the client's runtime history indexer is not be more than
	// number of versions kept behind the tip of the chain, as otherwise consensus
	// state pruning might be blocked by min reindexed height.

	if err := ensurePruned( // Consensus state
		beforePrune.Consensus.StateDB.LatestVersion-offlinePruningNumKept,
		afterPrune.Consensus.StateDB.LastRetainedVersion,
	); err != nil {
		return fmt.Errorf("consensus state not pruned as expected: %w", err)
	}

	if err := ensurePruned( // Consensus block history
		beforePrune.Consensus.BlockHistory.LatestVersion-offlinePruningNumKept,
		afterPrune.Consensus.BlockHistory.LastRetainedVersion,
	); err != nil {
		return fmt.Errorf("consensus block history not pruned as expected: %w", err)
	}

	if err := client.Start(); err != nil {
		return fmt.Errorf("failed to start client node: %w", err)
	}
	if err := client.WaitReady(ctx); err != nil {
		return fmt.Errorf("client node failed to become ready: %w", err)
	}

	return nil
}

func (sc *offlinePruningImpl) fetchStorageInspectStatus(childEnv *env.Env, node *oasis.Node) (*cmdStorage.Status, error) {
	args := []string{
		"storage",
		"inspect",
		"--config", node.ConfigFile(),
		"--output", "json",
	}
	resp, err := oasisCli.RunSubCommandWithOutput(childEnv, sc.Logger, "storage-inspect", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect storage status: %w", err)
	}

	var status cmdStorage.Status
	if err = json.Unmarshal(resp.Bytes(), &status); err != nil {
		return nil, fmt.Errorf("failed to parse storage status: %w", err)
	}

	return &status, nil
}

func (sc *offlinePruningImpl) setPruningConfig(node *oasis.Node, numKept uint64) error {
	cfgBytes, err := os.ReadFile(node.ConfigFile())
	if err != nil {
		return fmt.Errorf("failed to read node config: %w", err)
	}

	var cfg config.Config
	if err = yaml.Unmarshal(cfgBytes, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal node config: %w", err)
	}
	cfg.Consensus.Prune.Strategy = abci.PruneKeepN.String()
	cfg.Consensus.Prune.NumKept = numKept

	cfgBytes, err = yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal node config: %w", err)
	}
	if err = os.WriteFile(node.ConfigFile(), cfgBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write node config: %w", err)
	}

	return nil
}

func (sc *offlinePruningImpl) runOfflinePruning(childEnv *env.Env, node *oasis.Node) error {
	args := []string{
		"storage",
		"prune-experimental",
		"--config", node.ConfigFile(),
	}
	if err := oasisCli.RunSubCommand(childEnv, sc.Logger, "offline-pruning", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to run offline pruning: %w", err)
	}
	return nil
}

func (sc *offlinePruningImpl) runOfflineCompaction(childEnv *env.Env, node *oasis.Node) error {
	args := []string{
		"storage",
		"compact-experimental",
		"--config", node.ConfigFile(),
	}
	if err := oasisCli.RunSubCommand(childEnv, sc.Logger, "offline-compaction", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to run offline compaction: %w", err)
	}
	return nil
}
