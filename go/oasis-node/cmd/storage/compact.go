package storage

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmtDBProvider "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

func newCompactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compact",
		Args:  cobra.NoArgs,
		Short: "trigger compaction for all databases",
		Long: `Optimize the storage for all databases by manually compacting the underlying storage engines.

WARNING: Ensure you have at least as much of a free disk as your largest database.
`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}

			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}

			if running {
				return fmt.Errorf("compaction can only be done when the node is not running")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir := cmdCommon.DataDir()

			logger.Info("Starting database compactions. This may take a while...")

			if err := compactConsensusDBs(dataDir); err != nil {
				return fmt.Errorf("failed to compact consensus databases: %w", err)
			}

			runtimes, err := registry.GetConfiguredRuntimeIDs()
			if err != nil {
				return fmt.Errorf("failed to get configured runtimes: %w", err)
			}
			for _, rt := range runtimes {
				if err := compactRuntimeDBs(dataDir, rt); err != nil {
					return fmt.Errorf("failed to compact runtime dbs (runtime ID: %s): %w", rt, err)
				}
			}

			return nil
		},
	}

	return cmd
}

func compactConsensusDBs(dataDir string) error {
	// Compact CometBFT managed databases: block store, evidence and state (NOT application state).
	if err := compactCometDBs(dataDir); err != nil {
		return fmt.Errorf("failed to compact CometBFT managed databases: %w", err)
	}

	// Compact consensus NodeDB (application state).
	ndb, close, err := openConsensusNodeDB(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus NodeDB: %w", err)
	}
	defer close()

	if err := ndb.Compact(); err != nil {
		return fmt.Errorf("failed to compact consensus node DB: %w", err)
	}

	return nil
}

func compactCometDBs(dataDir string) error {
	dir := fmt.Sprintf("%s/consensus/data", dataDir)

	var dbDirs []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".db") {
			dbDirs = append(dbDirs, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk dir %s: %w", dir, err)
	}

	if len(dbDirs) == 0 {
		return fmt.Errorf("zero database instances found")
	}

	for _, dbDir := range dbDirs {
		if err := compactCometDB(dbDir); err != nil {
			return fmt.Errorf("failed to compact %s: %w", dbDir, err)
		}
	}
	return nil
}

func compactCometDB(path string) error {
	logger := logger.With("path", path)
	db, err := cmtDBProvider.OpenBadger(path, logger)
	if err != nil {
		return fmt.Errorf("failed to open BadgerDB: %w", err)
	}
	defer db.Close()

	logger.Info("compacting")

	if err := db.Flatten(1); err != nil {
		return fmt.Errorf("failed to flatten db: %w", err)
	}

	logger.Info("compaction completed")

	return nil
}

func compactRuntimeDBs(dataDir string, rt common.Namespace) error {
	history, err := openRuntimeLightHistory(dataDir, rt)
	if err != nil {
		return fmt.Errorf("failed to open runtime history: %w", err)
	}
	defer history.Close()
	if err := history.Compact(); err != nil {
		return fmt.Errorf("failed to compact runtime history: %w", err)
	}
	ndb, err := openRuntimeStateDB(dataDir, rt)
	if err != nil {
		return fmt.Errorf("failed to open runtime state DB: %w", err)
	}
	defer ndb.Close()
	if err := ndb.Compact(); err != nil {
		return fmt.Errorf("failed to compact runtime state DB: %w", err)
	}
	return nil
}
