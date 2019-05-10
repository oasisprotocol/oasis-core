// Package node implements the node registry sub-commands.
package node

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
)

var (
	nodeCmd = &cobra.Command{
		Use:   "node",
		Short: "node registry backend utilities",
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered nodes",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterVerbose(cmd)
		},
		Run: doList,
	}

	logger = logging.GetLogger("cmd/registry/node")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, grpcRegistry.EntityRegistryClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := grpcRegistry.NewEntityRegistryClient(conn)

	return conn, client
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	nodes, err := client.GetNodes(context.Background(), &grpcRegistry.NodesRequest{})
	if err != nil {
		logger.Error("failed to query nodes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range nodes.GetNode() {
		var node node.Node
		if err = node.FromProto(v); err != nil {
			logger.Error("failed to de-serialize node",
				"err", err,
				"pb", v,
			)
			continue
		}

		var s string
		switch cmdFlags.Verbose() {
		case true:
			s = string(json.Marshal(&node))
		default:
			s = node.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

// Register registers the node sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		listCmd,
	} {
		nodeCmd.AddCommand(v)
	}

	cmdFlags.RegisterVerbose(listCmd)

	for _, v := range []*cobra.Command{
		listCmd,
	} {
		cmdGrpc.RegisterClientFlags(v, false)
	}

	parentCmd.AddCommand(nodeCmd)
}
