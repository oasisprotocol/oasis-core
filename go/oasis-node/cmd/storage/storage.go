// Package storage implements the storage sub-commands.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	badgerDB "github.com/dgraph-io/badger/v4"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmtConfig "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	cmtDBProvider "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
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
		Use:   "compact-experimental",
		Args:  cobra.NoArgs,
		Short: "EXPERIMENTAL: trigger compaction for all consensus databases",
		Long: `EXPERIMENTAL: Optimize the storage for all consensus databases by manually compacting the underlying storage engines.

WARNING: Ensure you have at least as much of a free disk as your largest database.
`,
		RunE: doDBCompactions,
	}

	pruneCmd = &cobra.Command{
		Use:   "prune-experimental",
		Args:  cobra.NoArgs,
		Short: "EXPERIMENTAL: trigger pruning for all consensus databases",
		RunE:  doPrune,
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

func doMigrate(cmd *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()

	runtimes, err := parseRuntimes(args)
	cobra.CheckErr(err)

	for _, rt := range runtimes {
		if pretty {
			fmt.Printf(" ** Upgrading storage database for runtime %v...\n", rt)
		}
		err := func() error {
			runtimeDir := runtimeConfig.GetRuntimeStateDir(dataDir, rt)
			history, err := openRuntimeLightHistory(dataDir, rt)
			if err != nil {
				return fmt.Errorf("error creating history provider: %w", err)
			}
			defer history.Close()

			nodeCfg := &db.Config{
				DB:        workerStorage.GetLocalBackendDBDir(runtimeDir, config.GlobalConfig.Storage.Backend),
				Namespace: rt,
			}

			helper := &migrateHelper{
				ctx:     cmd.Context(),
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

func doCheck(cmd *cobra.Command, args []string) error {
	dataDir := cmdCommon.DataDir()

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

			err := badger.CheckSanity(cmd.Context(), nodeCfg, display)
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

func doDBCompactions(_ *cobra.Command, args []string) error {
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

func doPrune(_ *cobra.Command, args []string) error {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	running, err := cmdCommon.IsNodeRunning()
	if err != nil {
		return fmt.Errorf("failed to ensure the node is not running: %w", err)
	}

	if running {
		return fmt.Errorf("pruning can only be done when the node is not running")
	}

	if config.GlobalConfig.Consensus.Prune.Strategy == cmtConfig.PruneStrategyNone {
		logger.Info("skipping consensus pruning since disabled in the config")
		return nil
	}

	runtimes, err := registry.GetConfiguredRuntimeIDs()
	if err != nil {
		return fmt.Errorf("failed to get configured runtimes: %w", err)
	}

	logger.Info("Starting consensus databases pruning. This may take a while...")

	if err := pruneConsensusDBs(
		cmdCommon.DataDir(),
		config.GlobalConfig.Consensus.Prune.NumKept,
		runtimes,
	); err != nil {
		return fmt.Errorf("failed to prune consensus databases: %w", err)
	}

	return nil
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

	if err := pruneConsensusNodeDB(ndb, retainHeight); err != nil {
		return fmt.Errorf("failed to prune application state: %w", err)
	}

	if err := pruneCometDBs(dataDir, int64(retainHeight)); err != nil {
		return fmt.Errorf("failed to prune CometBFT managed databases: %w", err)
	}

	return nil
}

func pruneConsensusNodeDB(ndb db.NodeDB, retainHeight uint64) error {
	startHeight := ndb.GetEarliestVersion()

	if retainHeight <= startHeight {
		logger.Info("consensus state already pruned", "retain_height", retainHeight, "start_height", startHeight)
		return nil
	}

	logger.Info("pruning consensus state", "start_height", startHeight, "retain_height", retainHeight)
	for h := startHeight; h < retainHeight; h++ {
		if err := ndb.Prune(h); err != nil {
			return fmt.Errorf("failed to prune version %d: %w", h, err)
		}

		if h%10_000 == 0 { // periodically sync to disk
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

// Register registers the client sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	storageMigrateCmd.Flags().AddFlagSet(bundle.Flags)
	storageCheckCmd.Flags().AddFlagSet(bundle.Flags)
	storageCmd.AddCommand(storageMigrateCmd)
	storageCmd.AddCommand(storageCheckCmd)
	storageCmd.AddCommand(storageRenameNsCmd)
	storageCmd.AddCommand(storageCompactCmd)
	storageCmd.AddCommand(pruneCmd)
	storageCmd.AddCommand(newInspectCmd())
	storageCmd.AddCommand(newCheckpointCmd())
	parentCmd.AddCommand(storageCmd)
}
