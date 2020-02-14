// Package control implements the control sub-commands.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	control "github.com/oasislabs/oasis-core/go/control/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	upgrade "github.com/oasislabs/oasis-core/go/upgrade/api"
)

var (
	shutdownWait = false

	controlCmd = &cobra.Command{
		Use:   "control",
		Short: "node control interface utilities",
	}

	controlIsSyncedCmd = &cobra.Command{
		Use:   "is-synced",
		Short: "exit with 0 if the node completed initial syncing, 1 if not",
		Run:   doIsSynced,
	}

	controlWaitSyncCmd = &cobra.Command{
		Use:   "wait-sync",
		Short: "wait for the node to complete initial syncing",
		Run:   doWaitSync,
	}

	controlShutdownCmd = &cobra.Command{
		Use:   "shutdown",
		Short: "request node shutdown on next epoch transition",
		Run:   doShutdown,
	}

	controlUpgradeBinaryCmd = &cobra.Command{
		Use:   "upgrade-binary <upgrade-descriptor>",
		Short: "submit an upgrade descriptor to the node and request shutdown",
		Args:  cobra.ExactArgs(1),
		Run:   doUpgradeBinary,
	}

	controlCancelUpgradeCmd = &cobra.Command{
		Use:   "cancel-upgrade",
		Short: "cancel a pending upgrade unless it is already in progress",
		Run:   doCancelUpgrade,
	}

	logger = logging.GetLogger("cmd/control")
)

// DoConnect connects to the runtime client grpc server.
func DoConnect(cmd *cobra.Command) (*grpc.ClientConn, control.NodeController) {
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

	client := control.NewNodeControllerClient(conn)

	return conn, client
}

func doIsSynced(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	logger.Debug("querying synced status")

	// Use background context to block until the result comes in.
	synced, err := client.IsSynced(context.Background())
	if err != nil {
		logger.Error("failed to query synced status",
			"err", err,
		)
		os.Exit(128)
	}
	if synced {
		fmt.Println("node completed initial syncing")
		os.Exit(0)
	} else {
		fmt.Println("node has not completed initial syncing")
		os.Exit(1)
	}
}

func doWaitSync(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	logger.Debug("waiting for sync status")

	// Use background context to block until the result comes in.
	err := client.WaitSync(context.Background())
	if err != nil {
		logger.Error("failed to wait for sync status",
			"err", err,
		)
		os.Exit(1)
	}
}

func doShutdown(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	err := client.RequestShutdown(context.Background(), shutdownWait)
	if err != nil {
		logger.Error("failed to send shutdown request",
			"err", err,
		)
		os.Exit(1)
	}
}

func doUpgradeBinary(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	descriptorBytes, err := ioutil.ReadFile(args[0])
	if err != nil {
		logger.Error("failed to read upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	var desc upgrade.Descriptor
	if err = json.Unmarshal(descriptorBytes, &desc); err != nil {
		logger.Error("can't parse upgrade descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	if !desc.IsValid() {
		logger.Error("submitted upgrade descriptor is not valid")
		os.Exit(1)
	}

	if err = client.UpgradeBinary(context.Background(), &desc); err != nil {
		logger.Error("error while sending upgrade descriptor to the node",
			"err", err,
		)
		os.Exit(1)
	}
}

func doCancelUpgrade(cmd *cobra.Command, args []string) {
	conn, client := DoConnect(cmd)
	defer conn.Close()

	err := client.CancelUpgrade(context.Background())
	if err != nil {
		logger.Error("failed to send upgrade cancellation request",
			"err", err,
		)
		os.Exit(1)
	}
}

// Register registers the client sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	controlCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)

	controlShutdownCmd.Flags().BoolVarP(&shutdownWait, "wait", "w", false, "wait for the node to finish shutdown")

	controlCmd.AddCommand(controlIsSyncedCmd)
	controlCmd.AddCommand(controlWaitSyncCmd)
	controlCmd.AddCommand(controlShutdownCmd)
	controlCmd.AddCommand(controlUpgradeBinaryCmd)
	controlCmd.AddCommand(controlCancelUpgradeCmd)
	parentCmd.AddCommand(controlCmd)
}
