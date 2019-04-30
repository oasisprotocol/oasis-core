package compute

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/keymanager"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgWorkerEnabled = "worker.compute.enabled"

	cfgWorkerBackend = "worker.compute.backend"

	cfgWorkerRuntimeLoader = "worker.compute.runtime_loader"

	cfgRuntimeBinary = "worker.compute.runtime.binary"
	cfgRuntimeID     = "worker.compute.runtime.id"

	// XXX: This is needed till the code can watch the registry for runtimes.
	cfgRuntimeSGXIDs = "worker.compute.runtime.sgx_ids"

	cfgMaxQueueSize      = "worker.compute.leader.max_queue_size"
	cfgMaxBatchSize      = "worker.compute.leader.max_batch_size"
	cfgMaxBatchSizeBytes = "worker.compute.leader.max_batch_size_bytes"
	cfgMaxBatchTimeout   = "worker.compute.leader.max_batch_timeout"

	cfgStorageCommitTimeout = "worker.compute.storage_commit_timeout"

	cfgByzantineInjectDiscrepancies = "worker.byzantine.inject_discrepancies"
)

func getSGXRuntimeIDs() (map[signature.MapKey]bool, error) {
	m := make(map[signature.MapKey]bool)

	for _, v := range viper.GetStringSlice(cfgRuntimeSGXIDs) {
		var id signature.PublicKey
		if err := id.UnmarshalHex(v); err != nil {
			return nil, err
		}

		m[id.ToMapKey()] = true
	}

	return m, nil
}

// New creates a new worker.
func New(
	dataDir string,
	ias *ias.IAS,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
	syncable common.Syncable,
	keyManager *keymanager.KeyManager,
	registration *registration.Registration,
	workerCommonCfg *workerCommon.Config,
) (*Worker, error) {
	backend := viper.GetString(cfgWorkerBackend)
	workerRuntimeLoader := viper.GetString(cfgWorkerRuntimeLoader)

	// Setup runtimes.
	var runtimes []RuntimeConfig
	runtimeBinaries := viper.GetStringSlice(cfgRuntimeBinary)
	runtimeIDs := viper.GetStringSlice(cfgRuntimeID)
	if len(runtimeBinaries) != len(runtimeIDs) {
		return nil, fmt.Errorf("runtime binary/id count mismatch")
	}

	sgxRuntimeIDs, err := getSGXRuntimeIDs()
	if err != nil {
		return nil, err
	}

	for idx, runtimeBinary := range runtimeBinaries {
		var runtimeID signature.PublicKey
		if err = runtimeID.UnmarshalHex(runtimeIDs[idx]); err != nil {
			return nil, err
		}

		var teeHardware node.TEEHardware
		if sgxRuntimeIDs[runtimeID.ToMapKey()] {
			teeHardware = node.TEEHardwareIntelSGX
		}

		runtimes = append(runtimes, RuntimeConfig{
			ID:     runtimeID,
			Binary: runtimeBinary,
			// XXX: This is needed till the code can watch the registry for runtimes.
			TEEHardware: teeHardware,
		})
	}

	maxQueueSize := uint64(viper.GetInt(cfgMaxQueueSize))
	maxBatchSize := uint64(viper.GetInt(cfgMaxBatchSize))
	maxBatchSizeBytes := uint64(viper.GetSizeInBytes(cfgMaxBatchSizeBytes))
	maxBatchTimeout := viper.GetDuration(cfgMaxBatchTimeout)

	cfg := Config{
		Backend: backend,
		Committee: committee.Config{
			MaxQueueSize:      maxQueueSize,
			MaxBatchSize:      maxBatchSize,
			MaxBatchSizeBytes: maxBatchSizeBytes,
			MaxBatchTimeout:   maxBatchTimeout,

			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),

			ByzantineInjectDiscrepancies: viper.GetBool(cfgByzantineInjectDiscrepancies),
		},
		WorkerRuntimeLoaderBinary: workerRuntimeLoader,
		Runtimes:                  runtimes,
	}

	return newWorker(dataDir, viper.GetBool(cfgWorkerEnabled), identity, storage, roothash,
		registry, epochtime, scheduler, syncable, ias, registration, keyManager, cfg, workerCommonCfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable compute worker process")

		cmd.Flags().String(cfgWorkerBackend, "sandboxed", "Worker backend")

		cmd.Flags().String(cfgWorkerRuntimeLoader, "", "Path to worker process runtime loader binary")

		cmd.Flags().StringSlice(cfgRuntimeBinary, nil, "Path to runtime binary")
		cmd.Flags().StringSlice(cfgRuntimeID, nil, "Runtime ID")

		// XXX: This is needed till the code can watch the registry for runtimes.
		cmd.Flags().StringSlice(cfgRuntimeSGXIDs, nil, "SGX runtime IDs")

		cmd.Flags().Uint64(cfgMaxQueueSize, 10000, "Maximum size of the incoming queue")
		cmd.Flags().Uint64(cfgMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
		cmd.Flags().String(cfgMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")
		cmd.Flags().Duration(cfgMaxBatchTimeout, 1*time.Second, "Maximum amount of time to wait for a batch")

		cmd.Flags().Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

		cmd.Flags().Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies into batches")
	}

	for _, v := range []string{
		cfgWorkerEnabled,

		cfgWorkerBackend,

		cfgWorkerRuntimeLoader,

		cfgRuntimeBinary,
		cfgRuntimeID,

		cfgRuntimeSGXIDs,

		cfgMaxQueueSize,
		cfgMaxBatchSize,
		cfgMaxBatchSizeBytes,
		cfgMaxBatchTimeout,

		cfgStorageCommitTimeout,

		cfgByzantineInjectDiscrepancies,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
