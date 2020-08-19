// Package control implements the control debug sub-commands.
package control

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdControl "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/control"
)

var (
	epoch uint64
	nodes int

	controlCmd = &cobra.Command{
		Use:   "control",
		Short: "debug control node during tests",
	}

	controlSetEpochCmd = &cobra.Command{
		Use:   "set-epoch",
		Short: "set mock epochtime",
		Run:   doSetEpoch,
	}

	controlWaitNodesCmd = &cobra.Command{
		Use:   "wait-nodes",
		Short: "wait for specific number of nodes to register",
		Run:   doWaitNodes,
	}

	controlWaitReadyCmd = &cobra.Command{
		Use:   "wait-ready",
		Short: "wait for node to become ready",
		Long: "Wait for the consensus backend to be synced and runtimes being registered, " +
			"initialized, and ready to accept the workload.",
		Run: doWaitReady,
	}

	logger = logging.GetLogger("cmd/debug/control")
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

	if err := client.SetEpoch(context.Background(), beacon.EpochTime(epoch)); err != nil {
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

func doWaitReady(cmd *cobra.Command, args []string) {
	conn, client := cmdControl.DoConnect(cmd)
	defer conn.Close()

	logger.Debug("waiting for ready status")

	// Use background context to block until the result comes in.
	err := client.WaitReady(context.Background())
	if err != nil {
		logger.Error("failed to wait for ready status",
			"err", err,
		)
		os.Exit(1)
	}
}

// Register registers the dummy sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	controlCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	controlSetEpochCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")
	controlWaitNodesCmd.Flags().IntVarP(&nodes, "nodes", "n", 1, "number of nodes to wait for")

	controlCmd.AddCommand(controlSetEpochCmd)
	controlCmd.AddCommand(controlWaitNodesCmd)
	controlCmd.AddCommand(controlWaitReadyCmd)
	parentCmd.AddCommand(controlCmd)
}
