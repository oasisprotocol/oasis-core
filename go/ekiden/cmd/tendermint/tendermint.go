// Package tendermint implements the tendermint sub-commands.
package tendermint

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/tendermint"
)

const cfgGenesisFile = "genesis_file"

var (
	tendermintCmd = &cobra.Command{
		Use:   "tendermint",
		Short: "tendermint backend utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init_genesis [validator identity JSON files]...",
		Short: "initialize the genesis file",
		Args: func(cmd *cobra.Command, args []string) error {
			nrFn := cobra.MinimumNArgs(1)
			if err := nrFn(cmd, args); err != nil {
				return err
			}

			return nil
		},
		Run: doInitGenesis,
	}

	flagGenesisFile string

	logger = logging.GetLogger("cmd/tendermint")
)

func doInitGenesis(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	validators := make([]*tendermint.GenesisValidator, 0, len(args))
	for _, v := range args {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			logger.Error("failed to load genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}

		var validator tendermint.GenesisValidator
		if err := json.Unmarshal(b, &validator); err != nil {
			logger.Error("failed to parse genesis validator",
				"err", err,
				"filename", v,
			)
			return
		}
		validator.Power = 10 // TODO: Make this configurable.

		validators = append(validators, &validator)
	}

	doc := &tendermint.GenesisDocument{
		Validators:  validators,
		GenesisTime: time.Now(),
	}

	b, _ := json.Marshal(doc)
	if err := ioutil.WriteFile(flagGenesisFile, b, 0600); err != nil {
		logger.Error("failed to save generated genesis document",
			"err", err,
		)
		return
	}

	ok = true
}

// Register registers the tendermint sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	initGenesisCmd.Flags().StringVar(&flagGenesisFile, cfgGenesisFile, "genesis.json", "path to created genesis document")
	initProvisionValidatorCmd(tendermintCmd)

	for _, v := range []string{
		cfgGenesisFile,
	} {
		_ = viper.BindPFlag(v, initGenesisCmd.Flags().Lookup(v))
	}

	for _, v := range []*cobra.Command{
		initGenesisCmd,
	} {
		tendermintCmd.AddCommand(v)
	}

	parentCmd.AddCommand(tendermintCmd)
}
