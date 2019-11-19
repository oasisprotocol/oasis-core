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
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	consensusClient "github.com/oasislabs/oasis-core/go/consensus/client"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
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

	logger = logging.GetLogger("cmd/consensus")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, consensusAPI.ClientBackend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client, err := consensusClient.New(conn)
	if err != nil {
		logger.Error("failed to create consensus client",
			"err", err,
		)
		os.Exit(1)
	}
	return conn, client
}

func doSubmitTx(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

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

	if err = client.SubmitTx(context.Background(), &tx); err != nil {
		logger.Error("failed to submit transaction",
			"err", err,
		)
		os.Exit(1)
	}
}

// Register registers the consensus sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		submitTxCmd,
	} {
		consensusCmd.AddCommand(v)
	}

	submitTxCmd.Flags().AddFlagSet(cmdConsensus.TxFileFlags)
	submitTxCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)

	parentCmd.AddCommand(consensusCmd)
}
