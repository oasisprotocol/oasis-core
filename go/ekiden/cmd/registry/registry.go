// Package registry implements the registry sub-commands.
package registry

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/grpc/registry"
)

var (
	registryCmd = &cobra.Command{
		Use:   "registry",
		Short: "registry backend utilities",
	}

	registryListRuntimesCmd = &cobra.Command{
		Use:   "list-runtimes",
		Short: "list registered runtimes",
		Run:   doListRuntimes,
	}

	logger = logging.GetLogger("cmd/registry")
)

func doRuntimeConnect(cmd *cobra.Command) (*grpc.ClientConn, registry.RuntimeRegistryClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := registry.NewRuntimeRegistryClient(conn)

	return conn, client
}

func doListRuntimes(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doRuntimeConnect(cmd)
	defer conn.Close()

	runtimes, err := client.GetRuntimes(context.Background(), &registry.RuntimesRequest{})
	if err != nil {
		logger.Error("failed to query runtimes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range runtimes.Runtime {
		// At some point it would be cool to have a verbose flag to
		// pretty-print the entire entry.
		fmt.Printf("%v\n", hex.EncodeToString(v.Id))
	}
}

// Register registers the registry sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(registryListRuntimesCmd, false)

	registryCmd.AddCommand(registryListRuntimesCmd)
	parentCmd.AddCommand(registryCmd)
}
