// Package tendermint implements the tendermint identity sub-commands.
package tendermint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

var (
	tmCmd = &cobra.Command{
		Use:   "tendermint",
		Short: "tendermint backend utilities",
	}

	tmShowNodeAddressCmd = &cobra.Command{
		Use:   "show-node-address",
		Short: "outputs node's tendermint address",
		Run:   showNodeAddress,
	}

	tmShowConsensusAddressCmd = &cobra.Command{
		Use:   "show-consensus-address",
		Short: "outputs consensus' (validator's) tendermint address",
		Run:   showConsensusAddress,
	}

	logger = logging.GetLogger("cmd/identity/tendermint")

	tmFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func printTmAddress(desc, keyFile string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var pubKey signature.PublicKey

	if err := pubKey.LoadPEM(filepath.Join(cmdCommon.DataDir(), keyFile), nil); err != nil {
		logger.Error("failed to open node's public key",
			"err", err,
			"key_file", keyFile,
		)
		os.Exit(1)
	}

	tmAddress := crypto.PublicKeyToTendermint(&pubKey).Address()
	if cmdFlags.Verbose() {
		descBytes := []byte(desc)
		descBytes[0] = byte(unicode.ToUpper(rune(descBytes[0])))
		fmt.Printf("%s: %s (fingerprint: %X)\n", descBytes, tmAddress, tmbytes.Fingerprint(tmAddress))
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

// Register registers the tendermint sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	tmCmd.AddCommand(tmShowNodeAddressCmd)
	tmCmd.AddCommand(tmShowConsensusAddressCmd)

	tmShowNodeAddressCmd.Flags().AddFlagSet(tmFlags)
	tmShowConsensusAddressCmd.Flags().AddFlagSet(tmFlags)

	parentCmd.AddCommand(tmCmd)
}

func init() {
	tmFlags.AddFlagSet(cmdFlags.VerboseFlags)
}
