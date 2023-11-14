// Package platformdata implements the load platform data command.
package platformdata

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
)

const (
	efiVarsDir = "/sys/firmware/efi/efivars/"

	// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_DCAP_Multipackage_SW.pdf
	uefiVarServerRequest = "SgxRegistrationServerRequest-304e0796-d515-4698-ac6e-e76cb1a71c28"
)

const (
	cfgManifest = "platform-manifest"
)

var (
	loadPlatformDataCmd = &cobra.Command{
		Use:   "load-platform-data",
		Short: "loads platform data into node local storage",
		Run:   doLoadPlatformData,
	}

	platformDataFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/sgx/load-platform-data")
)

func doLoadPlatformData(_ *cobra.Command, _ []string) {
	config.GlobalConfig.Common.Log.Level["default"] = "info"
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	// Ensure node persistent store exists.
	// There doesn't seem to be an "open, but do not create" badger option.
	// Instead, check to see if the persistent store directory exists.
	dbPath := persistent.GetPersistentStoreDBDir(dataDir)
	fs, err := os.Stat(dbPath)
	if err != nil {
		cmdCommon.EarlyLogAndExit(fmt.Errorf("failed to stat persistent store directory: %w", err))
	}
	if !fs.IsDir() {
		cmdCommon.EarlyLogAndExit(fmt.Errorf("persistent store is not a directory"))
	}

	// Load the platform manifest.
	var platformManifest []byte
	data := viper.GetString(cfgManifest)
	switch {
	case data == "":
		logger.Info("using data provided on the command line")
		platformManifest, err = hex.DecodeString(data)
		if err != nil {
			cmdCommon.EarlyLogAndExit(fmt.Errorf("filed to decode platform manifest: %w", err))
		}
	default:
		path := filepath.Join(efiVarsDir, uefiVarServerRequest)
		logger.Info("loading data from UEFI variable", "path", path)

		var sgxVar []byte
		sgxVar, err = os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			cmdCommon.EarlyLogAndExit(fmt.Errorf("SgxRegistrationServerRequest UEFI variable not found"))
		case err != nil:
			cmdCommon.EarlyLogAndExit(fmt.Errorf("failed to read SgxRegistrationServerRequest UEFI variable: %w", err))
		default:
		}

		// Parse the UEFI variable: <unknown:4B> <version:2B> <size:2B> <platform manifest>.
		if len(sgxVar) < 8 {
			cmdCommon.EarlyLogAndExit(fmt.Errorf("unable to parse SgxRegistrationServerRequest UEFI variable (length < 8): %w", err))
		}
		offset := 4

		// Version.
		version := binary.LittleEndian.Uint16(sgxVar[offset : offset+2])
		if version != 2 {
			logger.Error("invalid UEFI variable version",
				"version", version)
			cmdCommon.EarlyLogAndExit(fmt.Errorf("unexpected SgxRegistrationServerRequest version: %d (expected: 2)", version))
		}
		offset += 2

		// Size.
		offset += 2

		// Platform manifest.
		platformManifest = sgxVar[offset:]
	}

	// TODO: maybe require force or approval when overriding.
	var manifest []byte
	if manifest, err = sgx.GetPlatformManifest(dataDir); err == nil {
		logger.Warn("platform manifest already exists, overwriting",
			"old", manifest,
			"new", platformManifest,
		)
	}

	// Store the platform manifest in the node local storage.
	if err = sgx.PersistPlatformManifest(dataDir, platformManifest); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
}

// Register registers the migrate-config sub-command.
func Register(parentCmd *cobra.Command) {
	loadPlatformDataCmd.PersistentFlags().AddFlagSet(platformDataFlags)
	parentCmd.AddCommand(loadPlatformDataCmd)
}

func init() {
	platformDataFlags.String(cfgManifest, "", "hex encoded platform manifest (if present, it will be used instead of the SGX UEFI variable)")
	_ = viper.BindPFlags(platformDataFlags)
}
