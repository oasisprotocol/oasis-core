package tendermint

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
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
		PreRun: func(cmd *cobra.Command, args []string) {
			registerProvisionValidatorFlags(cmd)
		},
		Run: doProvisionValidator,
	}

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
	if viper.GetBool(cfgInteractive) {
		if err = provisionInteractive(&validator); err != nil {
			logger.Error("failed to determine node parameters",
				"err", err,
			)
			os.Exit(1)
		}
	} else {
		// Validate the command line args.
		nodeName := viper.GetString(cfgNodeName)
		if err = nodeNameValidator(nodeName); err != nil {
			logger.Error("malformed node name",
				"err", err,
				"node_name", nodeName,
			)
			os.Exit(1)
		}

		nodeAddr := viper.GetString(cfgNodeAddr)
		if err = coreAddressValidator(nodeAddr); err != nil {
			logger.Error("malformed node address",
				"err", err,
				"node_addr", nodeAddr,
			)
			os.Exit(1)
		}

		// Populate the validator struct.
		validator.CoreAddress = nodeAddr
		validator.Name = common.NormalizeFQDN(nodeName)
	}

	// Write out the validator json to disk.
	f := viper.GetString(cfgValidatorFile)
	if f == "" {
		f = "validator-" + id.NodeKey.Public().String() + ".json"
	}
	if !filepath.IsAbs(f) {
		f = filepath.Join(dataDir, f)
	}
	b := json.Marshal(validator)
	if err = ioutil.WriteFile(f, b, 0600); err != nil {
		logger.Error("failed to write validator identity file",
			"err", err,
		)
		os.Exit(1)
	}
}

func provisionInteractive(validator *bootstrap.GenesisValidator) error {
	var qs []*survey.Question

	nodeName := viper.GetString(cfgNodeName)
	if nodeName == "" || common.IsFQDN(nodeName) != nil {
		nodeName, _ = os.Hostname()
	}
	qs = append(qs, &survey.Question{
		Name: "Name",
		Prompt: &survey.Input{
			Message: "Node name:",
			Default: nodeName,
		},
		Validate:  nodeNameValidator,
		Transform: survey.TransformString(common.NormalizeFQDN),
	})

	nodeAddr := viper.GetString(cfgNodeAddr)
	if nodeAddr == "" || common.IsAddrPort(nodeAddr) != nil {
		if addr := common.GuessExternalAddress(); addr != nil {
			nodeAddr = net.JoinHostPort(addr.String(), "26656")
		}
	}
	qs = append(qs, &survey.Question{
		Name: "CoreAddress",
		Prompt: &survey.Input{
			Message: "Tendermint core address:",
			Default: nodeAddr,
		},
		Validate: coreAddressValidator,
	})

	return survey.Ask(qs, validator)
}

func registerProvisionValidatorFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().BoolP(cfgInteractive, "i", false, "interactive")
		cmd.Flags().String(cfgNodeName, "", "validator node name")
		cmd.Flags().String(cfgNodeAddr, "", "validator node Tendermint core address")
		cmd.Flags().String(cfgValidatorFile, "", "validator identity file")
	}

	for _, v := range []string{
		cfgInteractive,
		cfgNodeAddr,
		cfgNodeName,
		cfgValidatorFile,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func initProvisionValidatorCmd(parentCmd *cobra.Command) {
	registerProvisionValidatorFlags(provisionValidatorCmd)

	parentCmd.AddCommand(provisionValidatorCmd)
}
