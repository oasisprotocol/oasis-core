package txnscheduler

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/keymanager"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/committee"
)

const (
	cfgWorkerEnabled = "worker.txnscheduler.enabled"

	cfgRuntimeID = "worker.txnscheduler.runtime.id"

	cfgMaxQueueSize      = "worker.txnscheduler.leader.max_queue_size"
	cfgMaxBatchSize      = "worker.txnscheduler.leader.max_batch_size"
	cfgMaxBatchSizeBytes = "worker.txnscheduler.leader.max_batch_size_bytes"
	cfgMaxBatchTimeout   = "worker.txnscheduler.leader.max_batch_timeout"

	cfgStorageCommitTimeout = "worker.txnscheduler.storage_commit_timeout"
)

// New creates a new worker.
func New(
	dataDir string,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
	syncable common.Syncable,
	keyManager *keymanager.KeyManager,
	p2p *p2p.P2P,
	registration *registration.Registration,
	workerCommonCfg *workerCommon.Config,
) (*Worker, error) {
	// Setup runtimes.
	var runtimes []RuntimeConfig
	runtimeIDs := viper.GetStringSlice(cfgRuntimeID)

	for _, runtimeIDStr := range runtimeIDs {
		var runtimeID signature.PublicKey
		if err := runtimeID.UnmarshalHex(runtimeIDStr); err != nil {
			return nil, err
		}

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

			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		},
		Runtimes: runtimes,
	}

	return newWorker(dataDir, viper.GetBool(cfgWorkerEnabled), identity, storage, roothash,
		registry, epochtime, scheduler, syncable, p2p, registration, keyManager, cfg, workerCommonCfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable transaction scheduler process")

		cmd.Flags().StringSlice(cfgRuntimeID, nil, "Runtime ID")

		cmd.Flags().Uint64(cfgMaxQueueSize, 10000, "Maximum size of the incoming queue")
		cmd.Flags().Uint64(cfgMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
		cmd.Flags().String(cfgMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")
		cmd.Flags().Duration(cfgMaxBatchTimeout, 1*time.Second, "Maximum amount of time to wait for a batch")

		cmd.Flags().Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")
	}

	for _, v := range []string{
		cfgWorkerEnabled,

		cfgRuntimeID,

		cfgMaxQueueSize,
		cfgMaxBatchSize,
		cfgMaxBatchSizeBytes,
		cfgMaxBatchTimeout,

		cfgStorageCommitTimeout,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
