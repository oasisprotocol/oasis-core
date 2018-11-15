package migrate

import (
	"encoding/hex"
	"io"
	"os"
	"sync"

	"github.com/eapache/channels"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/ugorji/go/codec"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	cfgExportBatchSize = "batch_size"
	cfgExportFile      = "output_file"
)

var (
	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "export storage",
		Run:   doExport,
	}

	flagExportBatchSize int
	flagExportFile      string
)

func doExport(cmd *cobra.Command, args []string) {
	logger := logging.GetLogger("cmd/storage/export")

	conn, client := doConnect(cmd, logger)
	defer conn.Close()

	logger.Info("exporting storage")

	ctx := osInterruptContext(logger)

	keyStream, err := client.GetKeys(ctx, &storage.GetKeysRequest{})
	if err != nil {
		logger.Error("failed to start streaming all keys",
			"err", err,
		)
		os.Exit(1)
	}

	wr, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgExportFile)
	if err != nil {
		logger.Error("failed to open output file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer wr.Close()
	}

	// TODO: It is not clear how this can recover gracefully on the off
	// chance that the batched requests exceed the gRPC limit.
	//
	// It is also not clear how useful this tool is, migration should
	// probably be done locally with per-backend tooling if required.

	if flagExportBatchSize <= 0 {
		flagExportBatchSize = 1
	}
	kiCh := channels.NewBatchingChannel(channels.BufferCap(flagExportBatchSize))
	wrCh := make(chan *dumpElement, flagExportBatchSize)

	var (
		wg       sync.WaitGroup
		keysOk   bool
		valuesOk bool
		writeOk  bool
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

	recvLoop:
		for {
			resp, err := keyStream.Recv()
			switch err {
			case nil:
			case io.EOF:
				kiCh.Close()
				break recvLoop
			default:
				logger.Error("failed to receive a key from stream",
					"err", err,
				)
				return
			}

			key := resp.GetKey()
			keyStr := hex.EncodeToString(key)
			if len(key) != api.KeySize {
				logger.Error("received invalid key",
					"key", keyStr,
				)
				return
			}

			logger.Debug("received key",
				"key", keyStr,
				"expiration", resp.GetExpiry(),
			)

			ki := &api.KeyInfo{
				Expiration: epochtime.EpochTime(resp.GetExpiry()),
			}
			copy(ki.Key[:], key)

			kiCh.In() <- ki
		}

		keysOk = true
	}()

	wg.Add(1)
	go func() {
		defer func() {
			close(wrCh)
			wg.Done()
		}()

		for tmp := range kiCh.Out() {
			kiVec := tmp.([]interface{})
			keys := make([]api.Key, 0, len(kiVec))
			expirations := make([]epochtime.EpochTime, 0, len(kiVec))
			var req storage.GetBatchRequest
			req.Ids = make([][]byte, 0, len(kiVec))

			logger.Debug("received batch",
				"batch_size", len(kiVec),
			)

			for _, v := range kiVec {
				ki := v.(*api.KeyInfo)
				keys = append(keys, ki.Key)
				expirations = append(expirations, ki.Expiration)
				req.Ids = append(req.Ids, ki.Key[:])
			}

			resp, err := client.GetBatch(ctx, &req)
			if err != nil {
				logger.Error("failed to get batch",
					"err", err,
				)
				return
			}

			values := resp.GetData()
			if len(values) != len(keys) {
				logger.Error("batch request reuturned unexpected number of values",
					"request_size", len(keys),
					"response_size", len(values),
				)
			}
			for i, key := range keys {
				value, expiration := values[i], expirations[i]

				if derived := api.HashStorageKey(value); derived != key {
					logger.Error("invariant violation H(value) != key",
						"key", hex.EncodeToString(key[:]),
						"derived", hex.EncodeToString(derived[:]),
					)
					return
				}

				select {
				case wrCh <- &dumpElement{
					Data:       value,
					Expiration: expiration,
				}:
				case <-ctx.Done():
					break
				}
			}
		}

		valuesOk = true
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var ch codec.CborHandle
		ch.EncodeOptions.ChanRecvTimeout = -1 // Till chan is closed.

		enc := codec.NewEncoder(wr, &ch)
		if err := enc.Encode(&wrCh); err != nil {
			logger.Error("failed to serialize output",
				"err", err,
			)
			return
		}

		writeOk = true
	}()

	wg.Wait()

	if !(keysOk && valuesOk && writeOk) {
		logger.Error("an error occured durring export, dump is incomplete")
		os.Exit(1)
	}

	logger.Info("export complete")
}

func registerExportCmd(parentCmd *cobra.Command) {
	cmdGrpc.RegisterClientFlags(exportCmd, false)

	exportCmd.Flags().IntVar(&flagExportBatchSize, cfgExportBatchSize, 1000, "export batch size")
	exportCmd.Flags().StringVarP(&flagExportFile, cfgExportFile, "o", "", "export output file")

	for _, v := range []string{
		cfgExportBatchSize,
		cfgExportFile,
	} {
		_ = viper.BindPFlag(v, exportCmd.Flags().Lookup(v))
	}

	parentCmd.AddCommand(exportCmd)
}
