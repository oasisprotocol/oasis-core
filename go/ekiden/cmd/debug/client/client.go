// Package client implements the client debug sub-commands.
package client

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	clientGrpc "github.com/oasislabs/ekiden/go/grpc/client"
)

var (
	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "node client interface utilities",
	}

	clientIsSyncedCmd = &cobra.Command{
		Use:   "is-synced",
		Short: "exit with 0 if the node completed initial syncing, 1 if not",
		Run:   doIsSynced,
	}

	logger = logging.GetLogger("cmd/client")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, clientGrpc.RuntimeClient) {
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

	client := clientGrpc.NewRuntimeClient(conn)

	return conn, client
}

func doIsSynced(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Debug("querying synced status")

	// Use background context to block until the result comes in.
	result, err := client.IsSynced(context.Background(), &clientGrpc.IsSyncedRequest{})
	if err != nil {
		logger.Error("failed to query synced status",
			"err", err,
		)
		os.Exit(128)
	}
	if result.Synced {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

// Register registers the client sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(clientCmd, true)

	clientCmd.AddCommand(clientIsSyncedCmd)
	parentCmd.AddCommand(clientCmd)
}
