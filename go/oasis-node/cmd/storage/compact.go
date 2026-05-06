package storage

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	badgerDB "github.com/dgraph-io/badger/v4"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmtDBProvider "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
)

func newCompactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compact-experimental",
		Args:  cobra.NoArgs,
		Short: "EXPERIMENTAL: trigger compaction for all consensus databases",
		Long: `EXPERIMENTAL: Optimize the storage for all consensus databases by manually compacting the underlying storage engines.

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

			// Compact CometBFT managed databases: block store, evidence and state (NOT application state).
			if err := compactCometDBs(dataDir); err != nil {
				return fmt.Errorf("failed to compact CometBFT managed databases: %w", err)
			}

			if err := compactConsensusNodeDB(dataDir); err != nil {
				return fmt.Errorf("failed to compact consensus NodeDB: %w", err)
			}

			return nil
		},
	}

	return cmd
}

func compactCometDBs(dataDir string) error {
	paths, err := findCometDBs(dataDir)
	if err != nil {
		return fmt.Errorf("failed to find database instances: %w", err)
	}
	for _, path := range paths {
		if err := compactCometDB(path); err != nil {
			return fmt.Errorf("failed to compact %s: %w", path, err)
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

	if err := flattenBadgerDB(db, logger); err != nil {
		return fmt.Errorf("failed to compact %s: %w", path, err)
	}

	return nil
}

func findCometDBs(dataDir string) ([]string, error) {
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
		return nil, fmt.Errorf("failed to walk dir %s: %w", dataDir, err)
	}

	if len(dbDirs) == 0 {
		return nil, fmt.Errorf("zero database instances found")
	}

	return dbDirs, nil
}

func flattenBadgerDB(db *badgerDB.DB, logger *logging.Logger) error {
	logger.Info("compacting")

	if err := db.Flatten(1); err != nil {
		return fmt.Errorf("failed to flatten db: %w", err)
	}

	logger.Info("compaction completed")

	return nil
}

func compactConsensusNodeDB(dataDir string) error {
	ndb, close, err := openConsensusNodeDB(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus NodeDB: %w", err)
	}
	defer close()

	return ndb.Compact()
}
