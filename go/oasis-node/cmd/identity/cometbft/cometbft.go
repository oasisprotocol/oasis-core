// Package cometbft implements the CometBFT identity sub-commands.
package cometbft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	cmtbytes "github.com/cometbft/cometbft/libs/bytes"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

const CfgDataDir = "datadir"

var (
	tmCmd = &cobra.Command{
		Use:   "cometbft",
		Short: "CometBFT backend utilities",
	}

	tmShowNodeAddressCmd = &cobra.Command{
		Use:   "show-node-address",
		Short: "outputs node's CometBFT address",
		Run:   showNodeAddress,
	}

	tmShowConsensusAddressCmd = &cobra.Command{
		Use:   "show-consensus-address",
		Short: "outputs consensus' (validator's) CometBFT address",
		Run:   showConsensusAddress,
	}

	logger = logging.GetLogger("cmd/identity/cometbft")

	tmFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func printTmAddress(desc, keyFile string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Workaround for viper bug: https://github.com/spf13/viper/issues/233
	_ = viper.BindPFlag(CfgDataDir, tmCmd.PersistentFlags().Lookup(CfgDataDir))

	dataDir := viper.GetString(CfgDataDir)
	if dataDir == "" {
		logger.Error("data directory must be set")
		os.Exit(1)
	}

	var pubKey signature.PublicKey

	if err := pubKey.LoadPEM(filepath.Join(dataDir, keyFile), nil); err != nil {
		logger.Error("failed to open node's public key",
			"err", err,
			"key_file", keyFile,
		)
		os.Exit(1)
	}

	tmAddress := crypto.PublicKeyToCometBFT(&pubKey).Address()
	if cmdFlags.Verbose() {
		descBytes := []byte(desc)
		descBytes[0] = byte(unicode.ToUpper(rune(descBytes[0])))
		fmt.Printf("%s: %s (fingerprint: %X)\n", descBytes, tmAddress, cmtbytes.Fingerprint(tmAddress))
	} else {
		fmt.Println(tmAddress)
	}
}

func showNodeAddress(cmd *cobra.Command, args []string) {
	desc := strings.TrimPrefix(cmd.Short, "outputs ")
	printTmAddress(desc, identity.P2PKeyPubFilename)
}

func showConsensusAddress(cmd *cobra.Command, args []string) {
	desc := strings.TrimPrefix(cmd.Short, "outputs ")
	printTmAddress(desc, identity.ConsensusKeyPubFilename)
}

// Register registers the cometbft sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	tmCmd.AddCommand(tmShowNodeAddressCmd)
	tmCmd.AddCommand(tmShowConsensusAddressCmd)

	tmCmd.PersistentFlags().AddFlagSet(tmFlags)

	parentCmd.AddCommand(tmCmd)
}

func init() {
	tmFlags.String(CfgDataDir, "", "data directory")
	tmFlags.AddFlagSet(cmdFlags.VerboseFlags)
	_ = viper.BindPFlags(tmFlags)
}
