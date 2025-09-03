// Package storage implements the storage sub-commands.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	badgerDB "github.com/dgraph-io/badger/v4"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

var (
	storageCmd = &cobra.Command{
		Use:   "storage",
		Short: "storage node utilities",
	}

	storageMigrateCmd = &cobra.Command{
		Use:   "migrate <runtime...>",
		Args:  cobra.MinimumNArgs(1),
		Short: "perform node database migration",
		RunE:  doMigrate,
	}

	storageCheckCmd = &cobra.Command{
		Use:   "check <runtime...>",
		Args:  cobra.MinimumNArgs(1),
		Short: "check node databases for consistency",
		RunE:  doCheck,
	}

	storageRenameNsCmd = &cobra.Command{
		Use:   "rename-ns <src-ns> <dst-ns>",
		Args:  cobra.ExactArgs(2),
		Short: "change the namespace of a runtime database",
		RunE:  doRenameNs,
	}

	storageCompactCmd = &cobra.Command{
		Use:   "compact",
		Args:  cobra.NoArgs,
		Short: "trigger compaction across all the databases",
		Long: `Optimize the storage for all the databases by doing the compaction.

It is recommended to call this before doing storage snapshots or copying the data to a remote node.`,
		RunE: doDbCompactions,
	}

	logger = logging.GetLogger("cmd/storage")

	pretty = cmdCommon.Isatty(1)
)

type displayHelper struct {
	lastTime     time.Time
	lastStatus   string
	lastProgress bool
}

func (dh *displayHelper) displayf(base, format string, args ...any) {
	dh.lastTime = time.Time{}
	if pretty {
		if dh.lastProgress {
			fmt.Printf("\n"+format, args...)
		} else {
			fmt.Printf(format, args...)
		}
	} else {
		logger.Info(base)
	}
	dh.lastProgress = false
	dh.lastStatus = base
}

func (dh *displayHelper) Display(msg string) {
	dh.displayf(msg, "- %s\n", msg)
}

func (dh *displayHelper) DisplayStepBegin(msg string) {
	dh.displayf(msg, "- %s... ", msg)
}

func (dh *displayHelper) DisplayStepEnd(msg string) {
	dh.displayf(msg, "\r- %s: %s\n", dh.lastStatus, msg)
}

func (dh *displayHelper) DisplayStep(msg string) {
	dh.displayf(msg, "- %s...\n", msg)
}

func (dh *displayHelper) DisplayProgress(msg string, current, total uint64) {
	if pretty {
		if time.Since(dh.lastTime).Seconds() < 0.1 && current < total {
			return
		}
		dh.lastTime = time.Now()

		var leadin string
		if len(dh.lastStatus) > 0 {
			leadin = fmt.Sprintf("- %s:", dh.lastStatus)
		} else {
			leadin = "-"
		}
		fmt.Printf("\r%s %s %.2f%% (%d / %d)\033[K", leadin, msg, (float64(current)/float64(total))*100.0, current, total)
		dh.lastProgress = true
	}
}

type migrateHelper struct {
	displayHelper

	ctx     context.Context
	history roothash.BlockHistory
	roots   map[hash.Hash]node.RootType
}

func (mh *migrateHelper) GetRootForHash(root hash.Hash, version uint64) ([]node.Root, error) {
	block, err := mh.history.GetBlock(mh.ctx, version)
	if err != nil {
		if errors.Is(err, roothash.ErrNotFound) {
			return nil, badger.ErrVersionNotFound
		}
		return nil, err
	}

	var roots []node.Root
	for _, blockRoot := range block.Header.StorageRoots() {
		if blockRoot.Hash.Equal(&root) {
			roots = append(roots, blockRoot)
		}
	}
	return roots, nil
}

func parseRuntimes(args []string) ([]common.Namespace, error) {
	var runtimes []common.Namespace
	for _, arg := range args {
		var runtimeID common.Namespace
		if err := runtimeID.UnmarshalHex(arg); err != nil {
			return nil, fmt.Errorf("malformed runtime identifier '%s': %w", arg, err)
		}
		runtimes = append(runtimes, runtimeID)
	}
	return runtimes, nil
}

func doMigrate(_ *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()
	ctx := context.Background()

	runtimes, err := parseRuntimes(args)
	cobra.CheckErr(err)

	for _, rt := range runtimes {
		if pretty {
			fmt.Printf(" ** Upgrading storage database for runtime %v...\n", rt)
		}
		err := func() error {
			runtimeDir := runtimeConfig.GetRuntimeStateDir(dataDir, rt)

			prunerFactory := history.NewNonePrunerFactory()
			history, err := history.New(rt, runtimeDir, prunerFactory, false)
			if err != nil {
				return fmt.Errorf("error creating history provider: %w", err)
			}
			defer history.Close()

			nodeCfg := &db.Config{
				DB:        workerStorage.GetLocalBackendDBDir(runtimeDir, config.GlobalConfig.Storage.Backend),
				Namespace: rt,
			}

			helper := &migrateHelper{
				ctx:     ctx,
				history: history,
				roots:   map[hash.Hash]node.RootType{},
			}

			newVersion, err := badger.Migrate(nodeCfg, helper)
			if err != nil {
				return fmt.Errorf("node database migrator returned error: %w", err)
			}
			logger.Info("successfully migrated node database", "new_version", newVersion)
			return nil
		}()
		if err != nil {
			logger.Error("error upgrading runtime", "rt", rt, "err", err)
			if pretty {
				fmt.Printf("error upgrading runtime %v: %v\n", rt, err)
			}
			return fmt.Errorf("error upgrading runtime %v: %w", rt, err)
		}
	}
	return nil
}

func doCheck(_ *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()
	ctx := context.Background()

	runtimes, err := parseRuntimes(args)
	cobra.CheckErr(err)

	for _, rt := range runtimes {
		if pretty {
			fmt.Printf("Checking storage database for runtime %v...\n", rt)
		}
		err := func() error {
			runtimeDir := runtimeConfig.GetRuntimeStateDir(dataDir, rt)

			nodeCfg := &db.Config{
				DB:        workerStorage.GetLocalBackendDBDir(runtimeDir, config.GlobalConfig.Storage.Backend),
				Namespace: rt,
			}

			display := &displayHelper{}

			err := badger.CheckSanity(ctx, nodeCfg, display)
			if err != nil {
				return fmt.Errorf("node database checker returned error: %w", err)
			}
			logger.Info("node database seems to be error-free", "rt", rt)
			return nil
		}()
		if err != nil {
			logger.Error("error checking node database", "rt", rt, "err", err)
			if pretty {
				fmt.Printf("error checking node database for runtime %v: %v\n", rt, err)
			}
			return fmt.Errorf("error checking node database for runtime %v: %w", rt, err)
		}
	}
	return nil
}

func doRenameNs(_ *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()

	if len(args) != 2 {
		return fmt.Errorf("need exactly two arguments (source and destination runtime IDs)")
	}

	var srcID, dstID common.Namespace
	if err := srcID.UnmarshalHex(args[0]); err != nil {
		return fmt.Errorf("malformed source runtime ID: %s", args[0])
	}
	if err := dstID.UnmarshalHex(args[1]); err != nil {
		return fmt.Errorf("malformed source runtime ID: %s", args[0])
	}
	if pretty {
		fmt.Printf("Renaming storage database for runtime from %s to %s...\n", srcID, dstID)
	}

	srcDir := runtimeConfig.GetRuntimeStateDir(dataDir, srcID)
	dstDir := runtimeConfig.GetRuntimeStateDir(dataDir, dstID)

	nodeCfg := &db.Config{
		DB:        workerStorage.GetLocalBackendDBDir(srcDir, config.GlobalConfig.Storage.Backend),
		Namespace: srcID,
	}

	err := badger.RenameNamespace(nodeCfg, dstID)
	if err != nil {
		return fmt.Errorf("failed to rename namespace: %w", err)
	}

	if err = os.Rename(srcDir, dstDir); err != nil {
		return fmt.Errorf("failed to move directory: %w", err)
	}

	// Remove history directory as that will be invalid now.
	if err = os.RemoveAll(filepath.Join(dstDir, history.DbFilename)); err != nil {
		return fmt.Errorf("failed to remove history directory: %w", err)
	}

	return nil
}

func doDbCompactions(_ *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()

	dbDirs, err := findDBInstances(dataDir)
	if err != nil {
		return fmt.Errorf("failed to find database instances: %w", err)
	}

	if len(dbDirs) == 0 {
		return fmt.Errorf("no database instances found (dataDir: %s)", dataDir)
	}

	if pretty {
		fmt.Println("Starting database compactions. This may take a while...")
	}

	for _, path := range dbDirs {
		if err := compactDB(path); err != nil {
			logger.Error("failed to compact", "path", path, "err", err)
			if pretty {
				fmt.Printf("Failed to compact %s: %v\n", path, err)
			}
		}
	}

	return nil
}

func findDBInstances(dataDir string) ([]string, error) {
	var dbDirs []string
	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
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

	return dbDirs, nil
}

func compactDB(path string) error {
	logger = logger.With("path", path)

	logger.Info("compacting")
	if pretty {
		fmt.Printf("Compacting %s\n", path)
	}

	opts := badgerDB.DefaultOptions(path).WithLogger(cmnBadger.NewLogAdapter(logger))
	db, err := badgerDB.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open db: %w", err)
	}
	defer db.Close()

	if err := db.Flatten(8); err != nil {
		return fmt.Errorf("failed to flatten db: %w", err)
	}

	logger.Info("compaction completed")
	if pretty {
		fmt.Printf("Compaction completed: %s\n", path)
	}

	return nil
}

// Register registers the client sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	storageMigrateCmd.Flags().AddFlagSet(bundle.Flags)
	storageCheckCmd.Flags().AddFlagSet(bundle.Flags)
	storageCmd.AddCommand(storageMigrateCmd)
	storageCmd.AddCommand(storageCheckCmd)
	storageCmd.AddCommand(storageRenameNsCmd)
	storageCmd.AddCommand(storageCompactCmd)
	parentCmd.AddCommand(storageCmd)
}
