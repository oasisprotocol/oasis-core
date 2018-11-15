package migrate

import (
	"os"

	"github.com/eapache/channels"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ugorji/go/codec"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/grpc/storage"
)

const (
	cfgImportBatchSize    = "batch_size"
	cfgImportCurrentEpoch = "current_epoch"
	cfgImportFile         = "input_file"
)

var (
	importCmd = &cobra.Command{
		Use:   "import",
		Short: "import storage",
		Run:   doImport,
	}

	flagImportBatchSize    int
	flagImportCurrentEpoch uint64
	flagImportFile         string
)

func doImport(cmd *cobra.Command, args []string) {
	logger := logging.GetLogger("cmd/storage/import")

	conn, client := doConnect(cmd, logger)
	defer conn.Close()

	logger.Info("importing storage")

	if flagImportCurrentEpoch == 0 {
		logger.Error("current epoch must be set via `--current_epoch`")
		os.Exit(1)
	}

	ctx := osInterruptContext(logger)

	rd, shouldClose, err := cmdCommon.GetInputReader(cmd, cfgImportFile)
	if err != nil {
		logger.Error("failed to open input file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer rd.Close()
	}

	if flagImportBatchSize <= 0 {
		flagImportBatchSize = 1
	}
	elemCh := channels.NewBatchingChannel(channels.BufferCap(flagImportBatchSize))

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)

		for tmp := range elemCh.Out() {
			elemVec := tmp.([]interface{})

			logger.Debug("received batch",
				"batch_size", len(elemVec),
			)

			var req storage.InsertBatchRequest
			req.Items = make([]*storage.InsertRequest, 0, len(elemVec))
			for _, v := range elemVec {
				elem := v.(*dumpElement)

				expiry := uint64(elem.Expiration)
				if expiry < flagImportCurrentEpoch {
					continue
				}
				expiry -= flagImportCurrentEpoch

				req.Items = append(req.Items, &storage.InsertRequest{
					Data:   elem.Data,
					Expiry: expiry,
				})
			}

			if _, err := client.InsertBatch(ctx, &req); err != nil {
				logger.Error("failed to insert batch",
					"err", err,
				)
				os.Exit(1)
			}
		}
	}()

	var ch codec.CborHandle
	dec := codec.NewDecoder(rd, &ch)
	typedCh := make(chan *dumpElement)
	go func() {
		for v := range typedCh {
			elemCh.In() <- v
		}
		elemCh.Close()
	}()
	if err := dec.Decode(&typedCh); err != nil {
		logger.Error("failed to decode element",
			"err", err,
		)
		os.Exit(1)
	}
	close(typedCh)

	<-doneCh

	logger.Info("import complete")
}

func registerImportCmd(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(importCmd, false)

	importCmd.Flags().IntVar(&flagImportBatchSize, cfgImportBatchSize, 1000, "import batch size")
	importCmd.Flags().Uint64Var(&flagImportCurrentEpoch, cfgImportCurrentEpoch, 0, "current epoch")
	importCmd.Flags().StringVarP(&flagImportFile, cfgImportFile, "i", "", "import input file")

	for _, v := range []string{
		cfgImportBatchSize,
		cfgImportCurrentEpoch,
		cfgImportFile,
	} {
		_ = viper.BindPFlag(v, importCmd.Flags().Lookup(v))
	}

	parentCmd.AddCommand(importCmd)
}
