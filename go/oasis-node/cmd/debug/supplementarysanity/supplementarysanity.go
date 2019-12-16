package supplementarysanity

import (
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/supplementarysanity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

const (
	// CfgEnabled enables the follow tool.
	CfgEnabled = "followtool.enabled"
	// CfgInterval sets the interval.
	CfgInterval = "followtool.interval"
)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgEnabled)
}

func New(tm service.TendermintService) error {
	fta := app.New(viper.GetInt64(CfgInterval))
	if err := tm.RegisterApplication(fta); err != nil {
		return errors.Wrap(err, "RegisterApplication followtool app")
	}
	return nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable follow tool")
	Flags.Int64(CfgInterval, 10, "Interval for checking Tendermint blocks (in blocks)")

	_ = viper.BindPFlags(Flags)
}
