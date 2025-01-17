package bundle

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// CfgDebugMockIDs configures mock runtime IDs for the purpose of testing.
const CfgDebugMockIDs = "runtime.debug.mock_ids"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.StringSlice(CfgDebugMockIDs, nil, "Mock runtime IDs (format: <path>,<path>,...)")
	_ = Flags.MarkHidden(CfgDebugMockIDs)

	_ = viper.BindPFlags(Flags)
}
