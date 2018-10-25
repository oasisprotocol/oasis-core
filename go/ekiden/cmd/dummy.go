package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	dummyAddress string
	epoch        uint64
	nodes        uint64

	dummyCmd = &cobra.Command{
		Use:   "dummy",
		Short: "control dummy node during tests",
	}

	dummySetEpochCmd = &cobra.Command{
		Use:   "set-epoch",
		Short: "set mock epochtime",
		Run:   dummySetEpoch,
	}

	dummyWaitNodesCmd = &cobra.Command{
		Use:   "wait-nodes",
		Short: "wait for specific number of nodes to register",
		Run:   dummyWaitNodes,
	}

	dummyLog = logging.GetLogger("cmd/dummy")
)

func dummyConnect() (*grpc.ClientConn, dummydebug.DummyDebugClient) {
	initCommon()

	conn, err := newGrpcClient(dummyAddress)
	if err != nil {
		dummyLog.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := dummydebug.NewDummyDebugClient(conn)

	return conn, client
}

func dummySetEpoch(cmd *cobra.Command, args []string) {
	conn, client := dummyConnect()
	defer conn.Close()

	dummyLog.Info("setting epoch",
		"epoch", epoch,
	)

	// Use background context to block until mock epoch transition is done.
	_, err := client.SetEpoch(context.Background(), &dummydebug.SetEpochRequest{Epoch: epoch})
	if err != nil {
		dummyLog.Error("failed to set epoch",
			"err", err,
		)
	}
}

func dummyWaitNodes(cmd *cobra.Command, args []string) {
	conn, client := dummyConnect()
	defer conn.Close()

	dummyLog.Info("waiting for nodes",
		"nodes", nodes,
	)

	// Use background context to block until all nodes register.
	_, err := client.WaitNodes(context.Background(), &dummydebug.WaitNodesRequest{Nodes: nodes})
	if err != nil {
		dummyLog.Error("failed to wait for nodes",
			"err", err,
		)
		os.Exit(1)
	}

	dummyLog.Info("enough nodes have been registered")
}

func init() {
	dummyCmd.PersistentFlags().StringVarP(&dummyAddress, "address", "a", defaultNodeAddress, "node gRPC address")
	dummySetEpochCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")
	dummyWaitNodesCmd.Flags().Uint64VarP(&nodes, "nodes", "n", 1, "number of nodes to wait for")

	rootCmd.AddCommand(dummyCmd)
	dummyCmd.AddCommand(dummySetEpochCmd)
	dummyCmd.AddCommand(dummyWaitNodesCmd)
}
