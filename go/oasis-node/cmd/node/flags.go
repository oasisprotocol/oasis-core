package node

import (
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	"github.com/oasisprotocol/oasis-core/go/ias"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	workerConsensusRPC "github.com/oasisprotocol/oasis-core/go/worker/consensusrpc"
	workerKeymanager "github.com/oasisprotocol/oasis-core/go/worker/keymanager"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage"
)

const (
	// CfgMode configures the Oasis node mode.
	CfgMode = "mode"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Register registers the node maintenance sub-commands and all of it's
// children.
func Register(parentCmd *cobra.Command) {
	unsafeResetCmd.Flags().AddFlagSet(flags.DryRunFlag)
	unsafeResetCmd.Flags().AddFlagSet(unsafeResetFlags)
	unsafeResetCmd.Flags().AddFlagSet(flags.ForceFlags)

	parentCmd.AddCommand(unsafeResetCmd)
}

func init() {
	Flags.String(CfgMode, "", "node mode (validator, compute, seed, keymanager, ...)")

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(flags.DebugTestEntityFlags)
	Flags.AddFlagSet(flags.DebugAllowRootFlag)
	Flags.AddFlagSet(flags.ConsensusValidatorFlag)
	Flags.AddFlagSet(flags.GenesisFileFlags)

	// Backend initialization flags.
	for _, v := range []*flag.FlagSet{
		metrics.Flags,
		cmdGrpc.ServerLocalFlags,
		cmdSigner.Flags,
		pprof.Flags,
		tendermint.Flags,
		seed.Flags,
		ias.Flags,
		workerKeymanager.Flags,
		runtimeRegistry.Flags,
		p2p.Flags,
		registration.Flags,
		workerCommon.Flags,
		workerStorage.Flags,
		workerSentry.Flags,
		workerConsensusRPC.Flags,
		crash.InitFlags(),
	} {
		Flags.AddFlagSet(v)
	}
}
