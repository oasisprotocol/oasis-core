package computeenable

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgWorkerEnabled enables the compute worker, tx scheduler worker, and merge worker.
	CfgWorkerEnabled = "worker.compute.enabled"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable compute worker processes")

	_ = viper.BindPFlags(Flags)
}
