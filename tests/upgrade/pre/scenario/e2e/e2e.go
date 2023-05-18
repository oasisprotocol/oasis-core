package e2e

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
)

const (
	// cfgUpgradeProtocolVersions is a comma separated list of consensus, host
	// and committee protocol versions.
	cfgUpgradeProtocolVersions = "upgrade.protocol_versions"
)

// upgradeFlags are command line flags for performing upgrades.
var upgradeFlags = flag.NewFlagSet("", flag.ContinueOnError)

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(e2e.E2eParamsDummy.Name(), e2e.E2eParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	upgradeFlags.String(cfgUpgradeProtocolVersions, "", "comma separated list of consensus, host and committee protocol versions")
	_ = viper.BindPFlags(upgradeFlags)

	cmd.RootCmd().Flags().AddFlagSet(upgradeFlags)
}
