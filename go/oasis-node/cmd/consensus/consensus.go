// Package consensus implements the consensus sub-commands.
package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

const (
	// CfgSignerPub is the public key of the account that will sign an unsigned transaction in estimate gas.
	CfgSignerPub = "consensus.signer_pub"
)

var (
	signerPub string

	consensusCmd = &cobra.Command{
		Use:        "consensus",
		Short:      "consensus backend commands",
		Deprecated: "use the `oasis` CLI instead.",
	}

	submitTxCmd = &cobra.Command{
		Use:        "submit_tx",
		Short:      "Submit a pre-signed transaction",
		Run:        doSubmitTx,
		Deprecated: "use the `oasis` CLI instead.",
	}

	showTxCmd = &cobra.Command{
		Use:        "show_tx",
		Short:      "Show the content a pre-signed transaction",
		Run:        doShowTx,
		Deprecated: "use the `oasis` CLI instead.",
	}

	estimateGasCmd = &cobra.Command{
		Use:        "estimate_gas",
		Short:      "Estimate how much gas a transaction will use",
		Run:        doEstimateGas,
		Deprecated: "use the `oasis` CLI instead.",
	}

	nextBlockStateCmd = &cobra.Command{
		Use:        "next_block_state",
		Run:        doNextBlockState,
		Deprecated: "use the `oasis` CLI instead.",
	}

	signEdenGenesisBlockCmd = &cobra.Command{
		Use:   "sign_eden_genesis_block",
		Short: "sign Eden genesis block",
		Run:   doSignEdenGenesisBlock,
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
	rawTx, err := os.ReadFile(viper.GetString(cmdConsensus.CfgTxFile))
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
	rawUnsignedTx, err := os.ReadFile(viper.GetString(cmdConsensus.CfgTxFile))
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

func doSubmitTx(cmd *cobra.Command, _ []string) {
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

func doShowTx(*cobra.Command, []string) {
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

func doEstimateGas(cmd *cobra.Command, _ []string) {
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

func doNextBlockState(cmd *cobra.Command, _ []string) {
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

func doSignEdenGenesisBlock(cmd *cobra.Command, _ []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
	dataDir := common.DataDir()

	// Prepare signer.
	signerFactory, err := cmdSigner.NewFactory(cmdSigner.Backend(), dataDir, identity.RequiredSignerRoles...)
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
	identity, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}
	signer := crypto.SignerToCometBFT(identity.ConsensusSigner)

	// Eden genesis block data
	chainContext := "bb3d748def55bdfb797a2ac53ee6ee141e54cd2ab2dc2375f4a0703a178e6e55"
	chainID := abciAPI.CometBFTChainID(chainContext)

	timeString := "2023-11-29 11:25:17.649247857 +0000 UTC"
	layout := "2006-01-02 15:04:05.999999999 -0700 MST"
	timestamp, err := time.Parse(layout, timeString)
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	blockHash, err := hex.DecodeString("7670c86852c214f4e2b5ad571f4c2c344c630afdb409f7a5a3adce5a85240f31")
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	headerHash, err := hex.DecodeString("4d2aeef8f066f67f5324590df7b0f1ca1c5198836743125898887787ed803155")
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Prepare signature.
	vote := cmtproto.Vote{
		Type:   2,
		Height: 16817956,
		Round:  2,
		BlockID: cmtproto.BlockID{
			Hash: blockHash,
			PartSetHeader: cmtproto.PartSetHeader{
				Total: 1,
				Hash:  headerHash,
			},
		},
		Timestamp: timestamp,
	}

	signBytes := cmttypes.VoteSignBytes(chainID, &vote)
	sig, err := signer.Sign(signBytes)
	if err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	fmt.Println(hex.EncodeToString(sig))
}

// Register registers the consensus sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		submitTxCmd,
		showTxCmd,
		estimateGasCmd,
		nextBlockStateCmd,
		signEdenGenesisBlockCmd,
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
