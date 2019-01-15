// Package benchmark implements the storage benchmark sub-command.
package benchmark

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage"
	storageAPI "github.com/oasislabs/ekiden/go/storage/api"
)

var (
	benchmarkStorageCmd = &cobra.Command{
		Use:   "benchmark",
		Short: "benchmark storage backend",
		Run:   doBenchmark,
	}
)

func doBenchmark(cmd *cobra.Command, args []string) {
	// Re-register flags due to https://github.com/spf13/viper/issues/233.
	RegisterFlags(cmd)

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger := logging.GetLogger("cmd/storage/benchmark")

	// Initialize the data directory.
	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		var err error
		dataDir, err = ioutil.TempDir("", "storage-benchmark")
		if err != nil {
			logger.Error("failed to initialize data directory",
				"err", err,
			)
			return
		}

		logger.Debug("using temporary data directory",
			"data_dir", dataDir,
		)

		defer os.RemoveAll(dataDir)
	}

	// Initialize the various backends.
	timeSource := mock.New()
	storage, err := storage.New(timeSource, dataDir)
	if err != nil {
		logger.Error("failed to initialize storage",
			"err", err,
		)
		return
	}
	defer storage.Cleanup()

	// Wait for storage initialization.
	<-storage.Initialized()

	for _, sz := range []int{
		256, 512, 1024, 4096, 8192, 16384, 32768,
	} {
		buf := make([]byte, sz)

		// Insert.
		var err error
		res := testing.Benchmark(func(b *testing.B) {
			b.SetBytes(int64(sz))
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				_, _ = io.ReadFull(rand.Reader, buf)
				b.StartTimer()

				if err = storage.Insert(context.Background(), buf, 9001); err != nil {
					b.Fatalf("failed to Insert(): %v", err)
				}
			}
		})
		if err != nil {
			logger.Error("failed to Insert()", "err", err)
		} else {
			logger.Info("Insert",
				"sz", sz,
				"ns_per_op", res.NsPerOp(),
			)
		}

		// Get.
		key := storageAPI.HashStorageKey(buf)
		res = testing.Benchmark(func(b *testing.B) {
			b.SetBytes(int64(sz))
			for i := 0; i < b.N; i++ {
				var tmp []byte
				tmp, err = storage.Get(context.Background(), key)
				if err != nil {
					b.Fatalf("failed to Get(): %v", err)
				}

				b.StopTimer()
				if !bytes.Equal(tmp, buf) {
					err = fmt.Errorf("bytes mismatch")
					b.Fatalf("bytes mismatch")
				}
				b.StartTimer()
			}
		})
		if err != nil {
			logger.Error("failed to Get()", "err", err)
		} else {
			logger.Info("Get",
				"sz", sz,
				"ns_per_op", res.NsPerOp(),
			)
		}
	}

	// PurgeExpired.
	sweeper, ok := storage.(storageAPI.SweepableBackend)
	if !ok {
		logger.Error("not Sweepable")
		return
	}
	res := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sweeper.PurgeExpired(0)
		}
	})
	logger.Info("PurgeExpired (none purged)",
		"ns_per_op", res.NsPerOp(),
	)
	sweeper.PurgeExpired(9002)
}

// RegisterFlags registers the flags used by the benchmark sub-command.
func RegisterFlags(cmd *cobra.Command) {
	for _, v := range []func(*cobra.Command){
		storage.RegisterFlags,
	} {
		v(cmd)
	}
}

// Register registers the storage benchmark sub-command.
func Register(parentCmd *cobra.Command) {
	RegisterFlags(benchmarkStorageCmd)
	parentCmd.AddCommand(benchmarkStorageCmd)
}
