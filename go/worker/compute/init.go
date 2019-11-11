package compute

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute/committee"
	"github.com/oasislabs/oasis-core/go/worker/merge"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

const (
	// CfgWorkerEnabled enables the compute worker.
	CfgWorkerEnabled = "worker.compute.enabled"

	cfgStorageCommitTimeout = "worker.compute.storage_commit_timeout"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

// New creates a new compute worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	mergeWorker *merge.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	cfg := Config{
		Committee: committee.Config{
			StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		},
	}

	return newWorker(dataDir, Enabled(), commonWorker, mergeWorker, registration, cfg)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable compute worker process")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	_ = viper.BindPFlags(Flags)
}
