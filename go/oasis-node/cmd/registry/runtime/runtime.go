// Package runtime implements the runtime registry sub-commands.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdContext "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/context"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	// CfgRuntimeDescriptor is the flag to specify the path to runtime descriptor.
	CfgRuntimeDescriptor = "runtime.descriptor"

	// CfgIncludeSuspended is the flag to include suspended runtimes.
	CfgIncludeSuspended = "include_suspended"
)

var (
	runtimeListFlags = flag.NewFlagSet("", flag.ContinueOnError)
	registerFlags    = flag.NewFlagSet("", flag.ContinueOnError)

	runtimeCmd = &cobra.Command{
		Use:   "runtime",
		Short: "runtime registry backend utilities",
	}

	registerCmd = &cobra.Command{
		Use:   "gen_register",
		Short: "generate a register runtime transaction",
		Run:   doGenRegister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered runtimes",
		Run:   doList,
	}

	logger = logging.GetLogger("cmd/registry/runtime")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, registry.Backend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := registry.NewRegistryClient(conn)
	return conn, client
}

func doGenRegister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	fileBytes, err := ioutil.ReadFile(viper.GetString(CfgRuntimeDescriptor))
	if err != nil {
		logger.Error("failed to read runtime descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	var rt registry.Runtime
	if err = json.Unmarshal(fileBytes, &rt); err != nil {
		logger.Error("can't parse runtime descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	if err = rt.ValidateBasic(true); err != nil {
		logger.Error("runtime descriptor is not valid",
			"err", err,
		)
		os.Exit(1)
	}
	if err = rt.Genesis.SanityCheck(false); err != nil {
		logger.Error("runtime descriptor genesis sanity check failure",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewRegisterRuntimeTx(nonce, fee, &rt)

	cmdConsensus.SignAndSaveTx(cmdContext.GetCtxWithGenesisInfo(genesis), tx, nil)
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	query := &registry.GetRuntimesQuery{
		Height:           consensus.HeightLatest,
		IncludeSuspended: viper.GetBool(CfgIncludeSuspended),
	}
	runtimes, err := client.GetRuntimes(context.Background(), query)
	if err != nil {
		logger.Error("failed to query runtimes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, rt := range runtimes {
		var rtString string
		switch cmdFlags.Verbose() {
		case true:
			prettyRt, err := cmdCommon.PrettyJSONMarshal(rt)
			if err != nil {
				logger.Error("failed to get pretty JSON of runtime",
					"err", err,
					"runtime ID", rt.ID.String(),
				)
				rtString = fmt.Sprintf("[invalid pretty JSON for runtime %s]", rt.ID)
			} else {
				rtString = string(prettyRt)
			}
		default:
			rtString = rt.ID.String()
		}

		fmt.Println(rtString)
	}
}

// Register registers the runtime sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		registerCmd,
		listCmd,
	} {
		runtimeCmd.AddCommand(v)
	}

	for _, v := range []*cobra.Command{
		registerCmd,
	} {
		v.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
	}

	listCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	listCmd.Flags().AddFlagSet(runtimeListFlags)

	registerCmd.Flags().AddFlagSet(registerFlags)

	parentCmd.AddCommand(runtimeCmd)
}

func init() {
	registerFlags.String(CfgRuntimeDescriptor, "", "Path to the runtime descriptor")
	_ = viper.BindPFlags(registerFlags)
	registerFlags.AddFlagSet(cmdSigner.Flags)
	registerFlags.AddFlagSet(cmdSigner.CLIFlags)
	registerFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	registerFlags.AddFlagSet(cmdConsensus.TxFlags)
	registerFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	// List Runtimes flags.
	runtimeListFlags.Bool(CfgIncludeSuspended, false, "Use to include suspended runtimes")
	_ = viper.BindPFlags(runtimeListFlags)
}
