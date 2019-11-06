package followtool

import (
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/followtool"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// cfgEnabled enables the follow tool.
const CfgEnabled = "followtool.enabled"

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgEnabled)
}

func New(tm service.TendermintService) error {
	fta := app.New()
	if err := tm.RegisterApplication(fta); err != nil {
		return errors.Wrap(err, "RegisterApplication followtool app")
	}
	return nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable follow tool")

	_ = viper.BindPFlags(Flags)
}
