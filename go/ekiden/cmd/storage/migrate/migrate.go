// Package migrate implements the storage migration sub-commands.
package migrate

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/grpc/storage"
)

type dumpElement struct {
	Data       []byte
	Expiration epochtime.EpochTime
}

func doConnect(cmd *cobra.Command, logger *logging.Logger) (*grpc.ClientConn, storage.StorageClient) {
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

	client := storage.NewStorageClient(conn)

	return conn, client
}

func osInterruptContext(logger *logging.Logger) context.Context {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Return a context that will be closed on SIGINT and nothing else.
	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		<-sigCh

		logger.Warn("user requested termination")

		cancelFn()
	}()

	return ctx
}

// Register registers the storage migration sub-commands.
func Register(parentCmd *cobra.Command) {
	registerExportCmd(parentCmd)
	registerImportCmd(parentCmd)
}
