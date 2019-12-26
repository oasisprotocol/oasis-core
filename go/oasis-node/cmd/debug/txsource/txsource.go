package txsource

import (
	"context"
	"crypto"
	"fmt"
	"math/rand"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/control/api"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

const (
	CfgWorkload = "workload"
	CfgSeed     = "seed"
)

var (
	logger      = logging.GetLogger("cmd/txsource")
	txsourceCmd = &cobra.Command{
		Use:   "txsource",
		Short: "send random transactions",
		RunE:  doRun,
	}
)

func doRun(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	// Set up the genesis system for the signature system's chain context.
	genesis, err := genesisFile.DefaultFileProvider()
	if err != nil {
		return fmt.Errorf("genesisFile.DefaultFileProvider: %w", err)
	}
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("genesis.GetGenesisDocument: %w", err)
	}
	logger.Debug("setting chain context", "chain_context", genesisDoc.ChainContext())
	genesisDoc.SetChainContext()

	// Resolve the workload.
	name := viper.GetString(CfgWorkload)
	w, ok := workload.ByName[name]
	if !ok {
		return fmt.Errorf("workload %s not found", name)
	}

	// Set up the deterministic random source.
	hash := crypto.SHA512
	seed := []byte(viper.GetString(CfgSeed))
	src, err := drbg.New(hash, seed, nil, []byte(fmt.Sprintf("txsource workload generator v1, workload %s", name)))
	if err != nil {
		return fmt.Errorf("drbg.New: %w", err)
	}
	rng := rand.New(mathrand.New(src))

	// Set up the gRPC client.
	logger.Debug("dialing node", "addr", viper.GetString(cmdGrpc.CfgAddress))
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		return fmt.Errorf("cmdGrpc.NewClient: %w", err)
	}
	defer conn.Close()

	// Set up the consensus client.
	cnsc := consensus.NewConsensusClient(conn)

	// Set up the runtime client.
	rtc := runtimeClient.NewRuntimeClient(conn)

	// Wait for sync before transferring control to the workload.
	ncc := api.NewNodeControllerClient(conn)
	logger.Debug("waiting for node sync")
	if err = ncc.WaitSync(context.Background()); err != nil {
		return fmt.Errorf("node controller client WaitSync: %w", err)
	}
	logger.Debug("node synced")

	logger.Debug("entering workload")
	if err = w.Run(rng, conn, cnsc, rtc); err != nil {
		return fmt.Errorf("workload: %w", err)
	}
	logger.Debug("workload returned")

	return nil
}

func Register(parentCmd *cobra.Command) {
	parentCmd.AddCommand(txsourceCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.String(CfgWorkload, workload.NameTransfer, "Name of the workload to run (see source for listing)")
	fs.String(CfgSeed, "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed", "Seed to use for randomized workloads")
	_ = viper.BindPFlags(fs)
	txsourceCmd.Flags().AddFlagSet(fs)

	txsourceCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
}
