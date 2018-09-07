package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	address string
	epoch   uint64

	dummyCmd = &cobra.Command{
		Use:   "dummy-set-epoch",
		Short: "Dummy epochtime controller",
		Run:   dummyController,
	}

	dummyLog = logging.GetLogger("dummy")
)

func dummyController(cmd *cobra.Command, args []string) {
	initCommon()

	// Establish gRPC connection to node.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		dummyLog.Error("failed to establish connection with node",
			"err", err,
		)
		return
	}
	defer conn.Close()

	client := dummydebug.NewDummyDebugClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dummyLog.Info("setting epoch",
		"epoch", epoch,
	)

	_, err = client.SetEpoch(ctx, &dummydebug.SetEpochRequest{Epoch: epoch})
	if err != nil {
		dummyLog.Error("failed to set epoch",
			"err", err,
		)
		return
	}
}

func init() {
	dummyCmd.PersistentFlags().StringVarP(&address, "address", "a", "127.0.0.1:42261", "node gRPC address")
	dummyCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")

	rootCmd.AddCommand(dummyCmd)
}
