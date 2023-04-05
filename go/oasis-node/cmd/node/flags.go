package node

import (
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Register registers the node maintenance sub-commands and all of it's
// children.
func Register(parentCmd *cobra.Command) {
	unsafeResetCmd.Flags().AddFlagSet(flags.DryRunFlag)
	unsafeResetCmd.Flags().AddFlagSet(unsafeResetFlags)
	unsafeResetCmd.Flags().AddFlagSet(flags.ForceFlags)

	// Workaround for viper bug: https://github.com/spf13/viper/issues/233
	_ = viper.BindPFlag(CfgDataDir, unsafeResetCmd.Flags().Lookup(CfgDataDir))

	parentCmd.AddCommand(unsafeResetCmd)
}

func init() {
	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(flags.DebugTestEntityFlags)

	// Backend initialization flags.
	for _, v := range []*flag.FlagSet{
		cmdGrpc.ServerLocalFlags,
		cmdSigner.Flags,
		runtimeRegistry.Flags,
		workerStorage.Flags,
		crash.InitFlags(),
	} {
		Flags.AddFlagSet(v)
	}
}
