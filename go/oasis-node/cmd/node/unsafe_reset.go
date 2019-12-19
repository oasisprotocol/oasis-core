package node

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
)

const (
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

	nodeStateGlobs = []string{
		"abci-mux-state.*.db",
		"persistent-store.*.db",
		tendermint.StateDir,
		runtimeRegistry.RuntimesDir,
	}

	localStorageGlob = "worker-local-storage.*.db"
	mkvsDatabaseGlob = "mkvs_storage.*.db"

	logger = logging.GetLogger("cmd/unsafe-reset")
)

func doUnsafeReset(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory must be set")
		return
	}

	isDryRun := cmdFlags.DryRun()
	if isDryRun {
		logger.Info("dry run, no modifications will be made to files")
	}

	globs := append([]string{}, nodeStateGlobs...)
	if viper.GetBool(CfgPreserveLocalStorage) {
		logger.Info("preserving untrusted local storage")
	} else {
		globs = append(globs, localStorageGlob)
	}
	if viper.GetBool(CfgPreserveMKVSDatabase) {
		logger.Info("preserving MKVS database")
	} else {
		globs = append(globs, mkvsDatabaseGlob)
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
	unsafeResetFlags.Bool(CfgPreserveLocalStorage, false, "preserve untrusted local storage")
	unsafeResetFlags.Bool(CfgPreserveMKVSDatabase, false, "preserve MKVS database")
	_ = viper.BindPFlags(unsafeResetFlags)
}
