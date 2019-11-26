// Package dummy implements the dummy debug sub-commands.
package dummy

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	control "github.com/oasislabs/oasis-core/go/control/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
)

var (
	epoch uint64
	nodes int

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

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, control.DebugController) {
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

	client := control.NewDebugControllerClient(conn)

	return conn, client
}

func doSetEpoch(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("setting epoch",
		"epoch", epoch,
	)

	if err := client.SetEpoch(context.Background(), epochtime.EpochTime(epoch)); err != nil {
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

	if err := client.WaitNodesRegistered(context.Background(), nodes); err != nil {
		logger.Error("failed to wait for nodes",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("enough nodes have been registered")
}

// Register registers the dummy sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	dummyCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	dummySetEpochCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")
	dummyWaitNodesCmd.Flags().IntVarP(&nodes, "nodes", "n", 1, "number of nodes to wait for")

	dummyCmd.AddCommand(dummySetEpochCmd)
	dummyCmd.AddCommand(dummyWaitNodesCmd)
	parentCmd.AddCommand(dummyCmd)
}
