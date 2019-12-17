package compute

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/merge"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

const (
	// CfgWorkerEnabled enables the compute worker.
	CfgWorkerEnabled = "worker.compute.enabled"
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
	return newWorker(dataDir, Enabled(), commonWorker, mergeWorker, registration)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable compute worker process")

	_ = viper.BindPFlags(Flags)
}
