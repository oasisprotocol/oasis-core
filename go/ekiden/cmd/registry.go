package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
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
		Run:   registryListRuntimes,
	}

	registryLog = logging.GetLogger("cmd/registry")
)

func registryRuntimeConnect() (*grpc.ClientConn, registry.RuntimeRegistryClient) {
	initCommon()

	conn, err := newGrpcClient(dummyAddress)
	if err != nil {
		registryLog.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := registry.NewRuntimeRegistryClient(conn)

	return conn, client
}

func registryListRuntimes(cmd *cobra.Command, args []string) {
	conn, client := registryRuntimeConnect()
	defer conn.Close()

	runtimes, err := client.GetRuntimes(context.Background(), &registry.RuntimesRequest{})
	if err != nil {
		registryLog.Error("failed to query runtimes",
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

func init() {
	registryCmd.PersistentFlags().StringVarP(&dummyAddress, "address", "a", defaultNodeAddress, "node gRPC address")

	rootCmd.AddCommand(registryCmd)
	registryCmd.AddCommand(registryListRuntimesCmd)
}
