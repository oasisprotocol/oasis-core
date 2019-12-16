// Package genesis implements the consensus sub-commands.
package consensus

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
)

var (
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

	cmdConsensus.InitGenesis()

	sigTx := loadTx()
	sigTx.PrettyPrint("", os.Stdout)
}

// Register registers the consensus sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		submitTxCmd,
		showTxCmd,
	} {
		consensusCmd.AddCommand(v)
	}

	submitTxCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	submitTxCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	showTxCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	showTxCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)

	parentCmd.AddCommand(consensusCmd)
}
