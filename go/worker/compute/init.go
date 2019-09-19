package compute

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
	"github.com/oasislabs/ekiden/go/worker/merge"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgWorkerEnabled = "worker.compute.enabled"

	cfgStorageCommitTimeout = "worker.compute.storage_commit_timeout"

	cfgByzantineInjectDiscrepancies = "worker.compute.byzantine.inject_discrepancies"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(cfgWorkerEnabled)
}

// New creates a new compute worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	mergeWorker *merge.Worker,
	registration *registration.Registration,
) (*Worker, error) {
	cfg := Config{
		Committee: committee.Config{
			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),

			ByzantineInjectDiscrepancies: viper.GetBool(cfgByzantineInjectDiscrepancies),
		},
	}

	return newWorker(dataDir, Enabled(), commonWorker, mergeWorker, registration, cfg)
}

func init() {
	Flags.Bool(cfgWorkerEnabled, false, "Enable compute worker process")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	Flags.Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies into batches")
	_ = Flags.MarkHidden(cfgByzantineInjectDiscrepancies)

	_ = viper.BindPFlags(Flags)
}
