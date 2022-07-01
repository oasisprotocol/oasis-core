// Package consensus implements the consensus sub-commands.
package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
)

const (
	// CfgSignerPub is the public key of the account that will sign an unsigned transaction in estimate gas.
	CfgSignerPub = "consensus.signer_pub"
)

var (
	signerPub string

	consensusCmd = &cobra.Command{
		Use:   "consensus",
		Short: "consensus backend commands",
	}

	submitTxCmd = &cobra.Command{
		Use:   "submit_tx",
		Short: "Submit a pre-signed transaction",
		Run:   doSubmitTx,
	}

	showTxCmd = &cobra.Command{
		Use:   "show_tx",
		Short: "Show the content a pre-signed transaction",
		Run:   doShowTx,
	}

	estimateGasCmd = &cobra.Command{
		Use:   "estimate_gas",
		Short: "Estimate how much gas a transactionw will use",
		Run:   doEstimateGas,
	}

	nextBlockStateCmd = &cobra.Command{
		Use: "next_block_state",
		Run: doNextBlockState,
	}

	logger = logging.GetLogger("cmd/consensus")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, consensus.ClientBackend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := consensus.NewConsensusClient(conn)
	return conn, client
}

func loadTx() *transaction.SignedTransaction {
	rawTx, err := ioutil.ReadFile(viper.GetString(cmdConsensus.CfgTxFile))
	if err != nil {
		logger.Error("failed to read raw serialized transaction",
			"err", err,
		)
		os.Exit(1)
	}

	var tx transaction.SignedTransaction
	if err = json.Unmarshal(rawTx, &tx); err != nil {
		logger.Error("failed to parse serialized transaction",
			"err", err,
		)
		os.Exit(1)
	}

	return &tx
}

func loadUnsignedTx() *transaction.Transaction {
	rawUnsignedTx, err := ioutil.ReadFile(viper.GetString(cmdConsensus.CfgTxFile))
	if err != nil {
		logger.Error("failed to read raw serialized unsigned transaction",
			"err", err,
		)
		os.Exit(1)
	}

	var tx transaction.Transaction
	if err = cbor.Unmarshal(rawUnsignedTx, &tx); err != nil {
		logger.Error("failed to parse serialized unsigned transaction",
			"err", err,
		)
		os.Exit(1)
	}

	return &tx
}

func doSubmitTx(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	tx := loadTx()

	if err := client.SubmitTx(context.Background(), tx); err != nil {
		logger.Error("failed to submit transaction",
			"err", err,
		)
		os.Exit(1)
	}
}

func doShowTx(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	genesis := cmdConsensus.InitGenesis()

	ctx := context.Background()
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, genesis.Staking.TokenSymbol)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, genesis.Staking.TokenValueExponent)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyGenesisHash, genesis.Hash())

	sigTx := loadTx()
	sigTx.PrettyPrint(ctx, "", os.Stdout)
}

func doEstimateGas(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	req := consensus.EstimateGasRequest{
		Transaction: loadUnsignedTx(),
	}
	if err := req.Signer.UnmarshalText([]byte(signerPub)); err != nil {
		logger.Error("failed to unmarshal signer public key",
			"err", err,
			"signer_pub_str", signerPub,
		)
		os.Exit(1)
	}
	gas, err := client.EstimateGas(context.Background(), &req)
	if err != nil {
		logger.Error("failed to estimate gas",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(gas)
}

func doNextBlockState(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	// Use background context to block until the result comes in.
	state, err := client.GetNextBlockState(context.Background())
	if err != nil {
		logger.Error("failed to query next block state",
			"err", err,
		)
		os.Exit(128)
	}
	prettyStatus, err := cmdCommon.PrettyJSONMarshal(state)
	if err != nil {
		logger.Error("failed to get pretty JSON of next block state status",
			"err", err,
		)
		os.Exit(1)
	}
	fmt.Println(string(prettyStatus))
}

// Register registers the consensus sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		submitTxCmd,
		showTxCmd,
		estimateGasCmd,
		nextBlockStateCmd,
	} {
		consensusCmd.AddCommand(v)
	}

	submitTxCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	submitTxCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	showTxCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	showTxCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)

	estimateGasCmd.Flags().StringVar(&signerPub, CfgSignerPub, "", "public key of the signer, in base64")
	estimateGasCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	estimateGasCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	nextBlockStateCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	parentCmd.AddCommand(consensusCmd)
}
