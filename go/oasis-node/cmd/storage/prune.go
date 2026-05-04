package storage

import (
	"fmt"
	"math"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmtConfig "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

var pruneDiskSyncInterval uint64 = 10_000

func newPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Args:  cobra.NoArgs,
		Short: "trigger pruning of all databases",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}

			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}
			if running {
				return fmt.Errorf("node is running")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := registry.GetConfiguredRuntimeIDs()
			if err != nil {
				return fmt.Errorf("failed to get configured runtimes: %w", err)
			}

			logger.Info("Starting databases pruning. This may take a while...")

			dataDir := cmdCommon.DataDir()

			// Consensus pruning
			if config.GlobalConfig.Consensus.Prune.Strategy == cmtConfig.PruneStrategyNone {
				logger.Info("skipping consensus pruning since disabled in the config")
			} else if err := pruneConsensusDBs(
				dataDir,
				config.GlobalConfig.Consensus.Prune.NumKept,
				runtimes,
			); err != nil {
				return fmt.Errorf("failed to prune consensus databases: %w", err)
			}

			// Runtime pruning
			if len(runtimes) == 0 {
				return nil
			}
			if config.GlobalConfig.Runtime.Prune.Strategy == "none" {
				logger.Info("skipping runtime pruning since disabled in the config")
				return nil
			}
			for _, rt := range runtimes {
				if err := pruneRuntimeDBs(
					dataDir,
					rt,
					config.GlobalConfig.Runtime.Prune.NumKept,
				); err != nil {
					return fmt.Errorf("failed to prune runtime databases (runtime ID: %s): %w", rt, err)
				}
			}

			return nil
		},
	}
	return cmd
}

func pruneConsensusDBs(dataDir string, numKept uint64, runtimes []common.Namespace) error {
	ndb, close, err := openConsensusNodeDB(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open NodeDB: %w", err)
	}
	defer close()

	latest, ok := ndb.GetLatestVersion()
	if !ok {
		logger.Info("skipping pruning as state db is empty")
		return nil
	}

	if latest < numKept {
		logger.Info("skipping pruning as the latest version is smaller than the number of versions to keep")
		return nil
	}

	// In case of configured runtimes, do not prune past the earliest reindexed
	// consensus height, so that light history can be populated correctly.
	minReindexed, err := minReindexedHeight(dataDir, runtimes)
	if err != nil {
		return fmt.Errorf("failed to fetch earliest reindexed consensus height: %w", err)
	}

	retainHeight := min(
		latest-numKept, // underflow not possible due to if above.
		uint64(minReindexed),
	)

	if err := pruneNodeDB(ndb, retainHeight); err != nil {
		return fmt.Errorf("failed to prune application state: %w", err)
	}

	if err := pruneCometDBs(dataDir, int64(retainHeight)); err != nil {
		return fmt.Errorf("failed to prune CometBFT managed databases: %w", err)
	}

	return nil
}

func pruneNodeDB(ndb db.NodeDB, retainVersion uint64) error {
	startVersion := ndb.GetEarliestVersion()

	if retainVersion <= startVersion {
		logger.Info("db state already pruned", "retain_version", retainVersion, "start_version", startVersion)
		return nil
	}

	logger.Info("pruning db state", "start_version", startVersion, "retain_version", retainVersion)
	for h := startVersion; h < retainVersion; h++ {
		if err := ndb.Prune(h); err != nil {
			return fmt.Errorf("failed to prune version %d: %w", h, err)
		}

		if pruneDiskSyncInterval != 0 && h%pruneDiskSyncInterval == 0 { // periodically sync to disk
			if err := ndb.Sync(); err != nil {
				return fmt.Errorf("failed to sync NodeDB: %w", err)
			}
			logger.Debug("forcing NodeDB disk sync during pruning", "version", h)
		}
	}

	if err := ndb.Sync(); err != nil {
		return fmt.Errorf("failed to sync NodeDB: %w", err)
	}

	return nil
}

// minReindexedHeight returns the smallest consensus height reindexed by any
// of the configured runtimes.
//
// In case of no configured runtimes it returns max int64.
func minReindexedHeight(dataDir string, runtimes []common.Namespace) (int64, error) {
	fetchLastReindexedHeight := func(runtimeID common.Namespace) (int64, error) {
		history, err := openRuntimeLightHistory(dataDir, runtimeID)
		if err != nil {
			return 0, fmt.Errorf("failed to open runtime light history: %w", err)
		}
		defer history.Close()

		h, err := history.LastConsensusHeight()
		if err != nil {
			return 0, fmt.Errorf("failed to get last consensus height: %w", err)
		}

		return h, nil
	}

	var minH int64 = math.MaxInt64
	for _, rt := range runtimes {
		h, err := fetchLastReindexedHeight(rt)
		if err != nil {
			return 0, fmt.Errorf("failed to fetch last reindexed height for %s: %w", rt, err)
		}

		if h < minH {
			minH = h
		}
	}

	return minH, nil
}

func pruneCometDBs(dataDir string, retainHeight int64) error {
	blockstore, err := openConsensusBlockstore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus blockstore: %w", err)
	}
	defer blockstore.Close()

	// Mimic the upstream pruning logic from CometBFT
	// (see https://github.com/oasisprotocol/cometbft/blob/653c9a0c95ac0f91a0c8c11efb9aa21c98407af6/state/execution.go#L655):
	// 1. Get the base from the blockstore
	// 2. Prune blockstore
	// 3. Prune statestore
	//
	// This ordering is problematic: if the blockstore pruning succeeds (updating the base) but
	// state DB pruning fails or is interrupted, a subsequent pruning run will skip already
	// pruned blocks while leaving part of the state DB unpruned.
	base := blockstore.Base()
	if retainHeight <= base {
		logger.Info("blockstore and state db already pruned")
		return nil
	}

	logger.Info("pruning consensus blockstore", "base", base, "retain_height", retainHeight)
	n, err := blockstore.PruneBlocks(retainHeight)
	if err != nil {
		return fmt.Errorf("failed to prune blocks (retain height: %d): %w", retainHeight, err)
	}
	logger.Info("blockstore pruning finished", "pruned", n)

	state, err := openConsensusStatestore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus state store: %w", err)
	}
	defer state.Close()

	logger.Info("pruning consensus states", "base", base, "retain_height", retainHeight)
	if err := state.PruneStates(base, retainHeight); err != nil {
		return fmt.Errorf("failed to prune state db (start: %d, end: %d): %w", base, retainHeight, err)
	}
	logger.Info("state db pruning finished")

	return nil
}

func pruneRuntimeDBs(dataDir string, runtimeID common.Namespace, numKept uint64) error {
	ndb, err := openRuntimeStateDB(dataDir, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to open runtime StateDB: %w", err)
	}
	defer ndb.Close()
	latest, ok := ndb.GetLatestVersion()
	if !ok {
		logger.Info("skipping pruning as state db is empty")
		return nil
	}

	if latest < numKept {
		logger.Info("skipping pruning as the latest version is smaller than the number of versions to keep")
		return nil
	}

	retainRound := latest - numKept
	if err := pruneNodeDB(ndb, retainRound); err != nil {
		return fmt.Errorf("failed to prune nodeDB: %w", err)
	}

	history, err := openRuntimeLightHistory(dataDir, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to open runtime light history: %w", err)
	}
	defer history.Close()
	if _, err := history.PruneBefore(retainRound); err != nil {
		return fmt.Errorf("failed to prune runtime history before round %d: %w", retainRound, err)
	}
	return nil
}
