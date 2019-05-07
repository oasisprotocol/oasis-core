package txnscheduler

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute"
	"github.com/oasislabs/ekiden/go/worker/registration"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/committee"
)

const (
	cfgWorkerEnabled = "worker.txnscheduler.enabled"

	cfgMaxQueueSize      = "worker.txnscheduler.leader.max_queue_size"
	cfgMaxBatchSize      = "worker.txnscheduler.leader.max_batch_size"
	cfgMaxBatchSizeBytes = "worker.txnscheduler.leader.max_batch_size_bytes"
	cfgMaxBatchTimeout   = "worker.txnscheduler.leader.max_batch_timeout"
)

// New creates a new worker.
func New(
	commonWorker *workerCommon.Worker,
	compute *compute.Worker,
	registration *registration.Registration,
) (*Worker, error) {
	// Setup runtimes.
	var runtimes []RuntimeConfig

	for _, runtimeID := range commonWorker.GetConfig().Runtimes {
		runtimes = append(runtimes, RuntimeConfig{
			ID: runtimeID,
		})
	}

	maxQueueSize := uint64(viper.GetInt(cfgMaxQueueSize))
	maxBatchSize := uint64(viper.GetInt(cfgMaxBatchSize))
	maxBatchSizeBytes := uint64(viper.GetSizeInBytes(cfgMaxBatchSizeBytes))
	maxBatchTimeout := viper.GetDuration(cfgMaxBatchTimeout)

	cfg := Config{
		Committee: committee.Config{
			MaxQueueSize:      maxQueueSize,
			MaxBatchSize:      maxBatchSize,
			MaxBatchSizeBytes: maxBatchSizeBytes,
			MaxBatchTimeout:   maxBatchTimeout,
		},
		Runtimes: runtimes,
	}

	return newWorker(viper.GetBool(cfgWorkerEnabled), commonWorker, compute, registration, cfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable transaction scheduler process")

		cmd.Flags().Uint64(cfgMaxQueueSize, 10000, "Maximum size of the incoming queue")
		cmd.Flags().Uint64(cfgMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
		cmd.Flags().String(cfgMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")
		cmd.Flags().Duration(cfgMaxBatchTimeout, 1*time.Second, "Maximum amount of time to wait for a batch")
	}

	for _, v := range []string{
		cfgWorkerEnabled,

		cfgMaxQueueSize,
		cfgMaxBatchSize,
		cfgMaxBatchSizeBytes,
		cfgMaxBatchTimeout,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
