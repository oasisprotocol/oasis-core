// Package pluginsigner implements the Oasis plugin-signer test scenario.
package pluginsigner

import (
	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	cfgPluginName   = "name"
	cfgPluginBinary = "binary"
	cfgPluginConfig = "config"
)

var pluginSignerParamsDummy = newPluginSignerImpl("")

type pluginSignerImpl struct {
	name   string
	logger *logging.Logger
	flags  *env.ParameterFlagSet
}

func newPluginSignerImpl(name string) *pluginSignerImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "plugin-signer"
	if name != "" {
		fullName += "/" + name
	}

	sc := &pluginSignerImpl{
		name:   fullName,
		logger: logging.GetLogger("scenario/" + fullName),
		flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.flags.String(cfgPluginName, "test-signer-plugin", "plugin name")
	sc.flags.String(cfgPluginBinary, "signer-plugin", "plugin binary")
	sc.flags.String(cfgPluginConfig, "", "plugin configuration")

	return sc
}

func (sc *pluginSignerImpl) Clone() pluginSignerImpl {
	return pluginSignerImpl{
		name:   sc.name,
		logger: sc.logger,
		flags:  sc.flags.Clone(),
	}
}

func (sc *pluginSignerImpl) Name() string {
	return sc.name
}

func (sc *pluginSignerImpl) Parameters() *env.ParameterFlagSet {
	return sc.flags
}

func (sc *pluginSignerImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *pluginSignerImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (sc *pluginSignerImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	return nil
}

// RegisterScenarios registers all scenarios for remote-signer.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(pluginSignerParamsDummy.Name(), pluginSignerParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Basic plugin signer test case.
		Basic,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}
