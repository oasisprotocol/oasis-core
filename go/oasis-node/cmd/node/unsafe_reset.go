package node

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmtCommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const (
	CfgDataDir = "datadir"

	// CfgPreserveLocalStorage exempts the untrusted local storage from
	// the unsafe-reset sub-command.
	CfgPreserveLocalStorage = "preserve.local_storage"

	// CfgPreserveMKVSDatabase exempts the MKVS database from the unsafe-reset
	// sub-command.
	CfgPreserveMKVSDatabase = "preserve.mkvs_database"
)

var (
	unsafeResetFlags = flag.NewFlagSet("", flag.ContinueOnError)

	unsafeResetCmd = &cobra.Command{
		Use:   "unsafe-reset",
		Short: "reset the node state (UNSAFE)",
		Run:   doUnsafeReset,
	}

	runtimesGlob = filepath.Join(runtimeRegistry.RuntimesDir, "*")

	nodeStateGlobs = []string{
		"persistent-store.*.db",
		cmtCommon.StateDir,
		filepath.Join(runtimesGlob, history.DbFilename),
	}

	runtimeLocalStorageGlob = filepath.Join(runtimesGlob, "worker-local-storage.*.db")
	runtimeMkvsDatabaseGlob = filepath.Join(runtimesGlob, "mkvs_storage.*.db")

	logger = logging.GetLogger("cmd/unsafe-reset")
)

func doUnsafeReset(*cobra.Command, []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := viper.GetString(CfgDataDir)
	if dataDir == "" {
		logger.Error("data directory must be set")
		return
	}

	// Do a state dir sanity check.
	for _, f := range []string{cmtCommon.StateDir, identity.NodeKeyPubFilename} {
		glob := filepath.Join(dataDir, f)
		matches, err := filepath.Glob(glob)
		if err != nil {
			logger.Error("invalid glob pattern",
				"err", err,
				"glob", glob,
			)
			return
		}
		if len(matches) == 0 && !cmdFlags.Force() {
			fmt.Printf("%s does not look like an oasis-node data directory, not removing any files. Use --force to run the command regardless.\n", dataDir)
			return
		}
	}

	isDryRun := cmdFlags.DryRun()
	if isDryRun {
		logger.Info("dry run, no modifications will be made to files")
	}

	globs := append([]string{}, nodeStateGlobs...)
	if viper.GetBool(CfgPreserveLocalStorage) {
		logger.Info("preserving untrusted local storage")
	} else {
		globs = append(globs, runtimeLocalStorageGlob)
	}
	if viper.GetBool(CfgPreserveMKVSDatabase) {
		logger.Info("preserving MKVS database")
	} else {
		globs = append(globs, runtimeMkvsDatabaseGlob)
	}

	// Enumerate the locations to purge.
	var pathsToPurge []string
	for _, v := range globs {
		glob := filepath.Join(dataDir, v)
		matches, err := filepath.Glob(glob)
		if err != nil {
			logger.Warn("failed to glob purge target",
				"err", err,
				"glob", glob,
			)
			return
		}

		if len(matches) == 0 {
			logger.Debug("candidate state location does not exist",
				"glob", glob,
			)
		} else {
			pathsToPurge = append(pathsToPurge, matches...)
		}
	}

	// Obliterate the state.
	for _, v := range pathsToPurge {
		logger.Info("removing on-disk node state",
			"path", v,
		)

		if !isDryRun {
			if err := os.RemoveAll(v); err != nil {
				logger.Error("failed to remove on-disk node state",
					"err", err,
					"path", v,
				)
			}
		}
	}

	logger.Info("state reset complete")

	ok = true
}

func init() {
	unsafeResetFlags.String(CfgDataDir, "", "data directory")
	unsafeResetFlags.Bool(CfgPreserveLocalStorage, true, "preserve per-runtime untrusted local storage")
	unsafeResetFlags.Bool(CfgPreserveMKVSDatabase, true, "preserve per-runtime MKVS database")
	_ = viper.BindPFlags(unsafeResetFlags)
}
