package common

import (
	"path/filepath"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
)

const (
	// StateDir is the name of the directory located inside the node's data
	// directory which contains the tendermint state.
	StateDir = "tendermint"

	// ConfigDir is the name of the Tendermint configuration directory.
	ConfigDir = "config"
)

const (
	// CfgCoreListenAddress configures the tendermint core network listen address.
	CfgCoreListenAddress = "consensus.tendermint.core.listen_address"

	// CfgDebugP2PAddrBookLenient configures allowing non-routable addresses.
	CfgDebugP2PAddrBookLenient = "consensus.tendermint.debug.addr_book_lenient"

	// CfgLogDebug configures Tendermint debug logging.
	CfgLogDebug = "consensus.tendermint.log.debug"

	// CfgSubmissionGasPrice configures the gas price used when submitting transactions.
	CfgSubmissionGasPrice = "consensus.tendermint.submission.gas_price"
	// CfgSubmissionMaxFee configures the maximum fee that can be set.
	CfgSubmissionMaxFee = "consensus.tendermint.submission.max_fee"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// InitDataDir initializes the data directory for Tendermint.
func InitDataDir(dataDir string) error {
	subDirs := []string{
		ConfigDir,
		"data", // Required by `tendermint/privval/FilePV.Save()`.
	}

	if err := common.Mkdir(dataDir); err != nil {
		return err
	}

	for _, subDir := range subDirs {
		if err := common.Mkdir(filepath.Join(dataDir, subDir)); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	Flags.String(CfgCoreListenAddress, "tcp://0.0.0.0:26656", "tendermint core listen address")
	Flags.Bool(CfgDebugP2PAddrBookLenient, false, "allow non-routable addresses")

	Flags.Uint64(CfgSubmissionGasPrice, 0, "gas price used when submitting consensus transactions")
	Flags.Uint64(CfgSubmissionMaxFee, 0, "maximum transaction fee when submitting consensus transactions")

	Flags.Bool(CfgLogDebug, false, "enable tendermint debug logs (very verbose)")

	_ = Flags.MarkHidden(CfgDebugP2PAddrBookLenient)
	_ = Flags.MarkHidden(CfgLogDebug)

	_ = viper.BindPFlags(Flags)
}
