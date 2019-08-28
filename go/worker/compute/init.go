package compute

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ias"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/client"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
	"github.com/oasislabs/ekiden/go/worker/merge"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgWorkerEnabled = "worker.compute.enabled"

	cfgWorkerBackend = "worker.compute.backend"

	cfgWorkerRuntimeLoader = "worker.compute.runtime_loader"

	cfgRuntimeBinary = "worker.compute.runtime.binary"

	// XXX: This is needed till the code can watch the registry for runtimes.
	cfgRuntimeSGXIDs = "worker.compute.runtime.sgx_ids"

	cfgStorageCommitTimeout = "worker.compute.storage_commit_timeout"

	cfgByzantineInjectDiscrepancies = "worker.compute.byzantine.inject_discrepancies"
)

// Flags has our flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

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

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(cfgWorkerEnabled)
}

// New creates a new worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	mergeWorker *merge.Worker,
	ias *ias.IAS,
	keyManager *keymanager.Client,
	registration *registration.Registration,
) (*Worker, error) {
	backend := viper.GetString(cfgWorkerBackend)
	workerRuntimeLoader := viper.GetString(cfgWorkerRuntimeLoader)

	// Setup runtimes.
	var runtimes []RuntimeConfig
	if Enabled() {
		runtimeBinaries := viper.GetStringSlice(cfgRuntimeBinary)
		if len(runtimeBinaries) != len(commonWorker.GetConfig().Runtimes) {
			return nil, fmt.Errorf("runtime binary/id count mismatch")
		}

		sgxRuntimeIDs, err := getSGXRuntimeIDs()
		if err != nil {
			return nil, err
		}

		for idx, runtimeBinary := range runtimeBinaries {
			runtimeID := commonWorker.GetConfig().Runtimes[idx]

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
	}

	cfg := Config{
		Backend: backend,
		Committee: committee.Config{
			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),

			ByzantineInjectDiscrepancies: viper.GetBool(cfgByzantineInjectDiscrepancies),
		},
		WorkerRuntimeLoaderBinary: workerRuntimeLoader,
		Runtimes:                  runtimes,
	}

	return newWorker(dataDir, Enabled(), commonWorker, mergeWorker,
		ias, keyManager, registration, cfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(Flags)
	}
}

func init() {
	Flags.Bool(cfgWorkerEnabled, false, "Enable compute worker process")

	Flags.String(cfgWorkerBackend, "sandboxed", "Worker backend")

	Flags.String(cfgWorkerRuntimeLoader, "", "Path to worker process runtime loader binary")

	Flags.StringSlice(cfgRuntimeBinary, nil, "Path to runtime binary")

	// XXX: This is needed till the code can watch the registry for runtimes.
	Flags.StringSlice(cfgRuntimeSGXIDs, nil, "SGX runtime IDs")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	Flags.Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies into batches")
	_ = Flags.MarkHidden(cfgByzantineInjectDiscrepancies)

	_ = viper.BindPFlags(Flags)
}
