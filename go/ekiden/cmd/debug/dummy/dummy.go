// Package dummy implements the dummy debug sub-commands.
package dummy

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	epoch uint64
	nodes uint64

	dummyCmd = &cobra.Command{
		Use:   "dummy",
		Short: "control dummy node during tests",
	}

	dummySetEpochCmd = &cobra.Command{
		Use:   "set-epoch",
		Short: "set mock epochtime",
		Run:   doSetEpoch,
	}

	dummyWaitNodesCmd = &cobra.Command{
		Use:   "wait-nodes",
		Short: "wait for specific number of nodes to register",
		Run:   doWaitNodes,
	}

	logger = logging.GetLogger("cmd/dummy")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, dummydebug.DummyDebugClient) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := dummydebug.NewDummyDebugClient(conn)

	return conn, client
}

func doSetEpoch(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("setting epoch",
		"epoch", epoch,
	)

	// Use background context to block until mock epoch transition is done.
	_, err := client.SetEpoch(context.Background(), &dummydebug.SetEpochRequest{Epoch: epoch})
	if err != nil {
		logger.Error("failed to set epoch",
			"err", err,
		)
	}
}

func doWaitNodes(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("waiting for nodes",
		"nodes", nodes,
	)

	// Use background context to block until all nodes register.
	_, err := client.WaitNodes(context.Background(), &dummydebug.WaitNodesRequest{Nodes: nodes})
	if err != nil {
		logger.Error("failed to wait for nodes",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("enough nodes have been registered")
}

// Register registers the dummy sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(dummyCmd, true)
	dummySetEpochCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")
	dummyWaitNodesCmd.Flags().Uint64VarP(&nodes, "nodes", "n", 1, "number of nodes to wait for")

	dummyCmd.AddCommand(dummySetEpochCmd)
	dummyCmd.AddCommand(dummyWaitNodesCmd)
	parentCmd.AddCommand(dummyCmd)
}
