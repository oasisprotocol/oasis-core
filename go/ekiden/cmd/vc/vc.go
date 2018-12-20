// Package vc implements the validator committee sub-commands.
package vc

import (
	"crypto/rand"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	tmed "github.com/tendermint/tendermint/crypto/ed25519"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
)

const (
	// Name of argument to specify the output genesis.json file.
	cfgGenesisFile = "genesis_file"

	// Name of argument to specify the output node identity file.
	cfgNodeIdentityFile = "node_identity"
)

var (
	vcCmd = &cobra.Command{
		Use:   "vc",
		Short: "validator committee utilities",
	}

	vcGenIdentityCmd = &cobra.Command{
		Use:   "gen_validator",
		Short: "generate a new validator node identity and output the genesis file",
		Run:   doGenValidator,
	}

	flagGenesisFile      string
	flagNodeIdentityFile string

	logger = logging.GetLogger("cmd/vc")
)

func doGenValidator(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	if flagGenesisFile == "" {
		logger.Error("output genesis file not set, use '--" + cfgGenesisFile + "'")
		return
	}
	if flagNodeIdentityFile == "" {
		logger.Error("output node identity file not set, use '--" + cfgNodeIdentityFile + "'")
		return
	}

	// Load existing or generate new node identity key.
	var ni signature.PrivateKey

	if err := ni.LoadPEM(flagNodeIdentityFile, rand.Reader); err != nil {
		logger.Error("failed to load or generate node key",
			"error", err)
		return
	}

	// Convert our key to Tendermint format.
	var tni tmed.PrivKeyEd25519
	copy(tni[:], ni[:])

	// Generate genesis file with the newly-created node as validator.
	gd := tmtypes.GenesisDoc{
		ChainID:         "0xa515",
		GenesisTime:     time.Now(),
		ConsensusParams: tmtypes.DefaultConsensusParams(),
	}
	gd.Validators = []tmtypes.GenesisValidator{{
		PubKey: tni.PubKey(),
		Power:  10,
	}}

	if err := gd.SaveAs(flagGenesisFile); err != nil {
		logger.Error("failed to save generated genesis JSON file",
			"error", err)
		return
	}
}

// Register registers the vc sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	vcGenIdentityCmd.Flags().StringVar(&flagGenesisFile, cfgGenesisFile, "", "path to output genesis.json file")
	vcGenIdentityCmd.Flags().StringVar(&flagNodeIdentityFile, cfgNodeIdentityFile, "", "path to output node identity file (p2p.pem)")

	for _, v := range []string{
		cfgGenesisFile,
		cfgNodeIdentityFile,
	} {
		viper.BindPFlag(v, vcGenIdentityCmd.Flags().Lookup(v)) // nolint: errcheck
	}

	vcCmd.AddCommand(vcGenIdentityCmd)
	parentCmd.AddCommand(vcCmd)
}
