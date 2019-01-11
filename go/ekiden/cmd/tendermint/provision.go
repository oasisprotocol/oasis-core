package tendermint

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/identity"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/tendermint/bootstrap"
)

const (
	cfgInteractive   = "interactive"
	cfgNodeName      = "node_name"
	cfgNodeAddr      = "node_addr"
	cfgValidatorFile = "validator_file"
)

var (
	provisionValidatorCmd = &cobra.Command{
		Use:   "provision_validator",
		Short: "provision a validator node",
		Run:   doProvisionValidator,
	}

	flagInteractive   bool
	flagNodeName      string
	flagNodeAddr      string
	flagValidatorFile string

	errNotString = errors.New("input is not a string")

	nodeNameValidator = survey.ComposeValidators(
		survey.Required,
		survey.MinLength(1),
		survey.MaxLength(255),
		func(ans interface{}) error {
			s, ok := ans.(string)
			if !ok {
				return errNotString
			}

			return common.IsFQDN(s)
		},
	)

	coreAddressValidator = survey.ComposeValidators(
		survey.Required,
		func(ans interface{}) error {
			s, ok := ans.(string)
			if !ok {
				return errNotString
			}

			return common.IsAddrPort(s)
		},
	)
)

func doProvisionValidator(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory not configured")
		os.Exit(1)
	}

	id, err := identity.LoadOrGenerate(dataDir)
	if err != nil {
		logger.Error("failed to load or generate node identity",
			"err", err,
		)
		os.Exit(1)
	}

	validator := bootstrap.GenesisValidator{
		PubKey: id.NodeKey.Public(),
	}

	// Interactively prompt if requested.
	if flagInteractive {
		if err = provisionInteractive(&validator); err != nil {
			logger.Error("failed to determine node parameters",
				"err", err,
			)
			os.Exit(1)
		}
	} else {
		// Validate the command line args.
		if err = nodeNameValidator(flagNodeName); err != nil {
			logger.Error("malformed node name",
				"err", err,
				"node_name", flagNodeName,
			)
			os.Exit(1)
		}
		if err = coreAddressValidator(flagNodeAddr); err != nil {
			logger.Error("malformed node address",
				"err", err,
				"node_addr", flagNodeAddr,
			)
			os.Exit(1)
		}

		// Populate the validator struct.
		validator.CoreAddress = flagNodeAddr
		validator.Name = common.NormalizeFQDN(flagNodeName)
	}

	// Write out the validator json to disk.
	if flagValidatorFile == "" {
		flagValidatorFile = "validator-" + id.NodeKey.Public().String() + ".json"
	}
	if !filepath.IsAbs(flagValidatorFile) {
		flagValidatorFile = filepath.Join(dataDir, flagValidatorFile)
	}
	b, _ := json.Marshal(validator)
	if err = ioutil.WriteFile(flagValidatorFile, b, 0600); err != nil {
		logger.Error("failed to write validator identity file",
			"err", err,
		)
		os.Exit(1)
	}
}

func provisionInteractive(validator *bootstrap.GenesisValidator) error {
	var qs []*survey.Question

	if flagNodeName == "" || common.IsFQDN(flagNodeName) != nil {
		flagNodeName, _ = os.Hostname()
	}
	qs = append(qs, &survey.Question{
		Name: "Name",
		Prompt: &survey.Input{
			Message: "Node name:",
			Default: flagNodeName,
		},
		Validate:  nodeNameValidator,
		Transform: survey.TransformString(common.NormalizeFQDN),
	})

	if flagNodeAddr == "" || common.IsAddrPort(flagNodeAddr) != nil {
		if addr := common.GuessExternalAddress(); addr != nil {
			flagNodeAddr = addr.String() + ":26656" // Default port.
		}
	}
	qs = append(qs, &survey.Question{
		Name: "CoreAddress",
		Prompt: &survey.Input{
			Message: "Tendermint core address:",
			Default: flagNodeAddr,
		},
		Validate: coreAddressValidator,
	})

	return survey.Ask(qs, validator)
}

func initProvisionValidatorCmd(parentCmd *cobra.Command) {
	provisionValidatorCmd.Flags().BoolVarP(&flagInteractive, cfgInteractive, "i", false, "interactive")
	provisionValidatorCmd.Flags().StringVar(&flagNodeName, cfgNodeName, "", "validator node name")
	provisionValidatorCmd.Flags().StringVar(&flagNodeAddr, cfgNodeAddr, "", "validator node Tendermint core address")
	provisionValidatorCmd.Flags().StringVar(&flagValidatorFile, cfgValidatorFile, "", "validator identity file")

	for _, v := range []string{
		cfgNodeAddr,
		cfgNodeName,
	} {
		_ = viper.BindPFlag(v, provisionValidatorCmd.Flags().Lookup(v))
	}

	parentCmd.AddCommand(provisionValidatorCmd)
}
