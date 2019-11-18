package txnscheduler

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	txnSchedulerAlgorithm "github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm"
)

const (
	// CfgWorkerEnabled enables the tx scheduler worker.
	CfgWorkerEnabled = "worker.txn_scheduler.enabled"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

// New creates a new worker.
func New(
	commonWorker *workerCommon.Worker,
	compute *compute.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	// Setup runtimes.
	var runtimes []RuntimeConfig

	for _, runtimeID := range commonWorker.GetConfig().Runtimes {
		runtimes = append(runtimes, RuntimeConfig{
			ID: runtimeID,
		})
	}

	cfg := Config{
		Runtimes: runtimes,
	}

	return newWorker(Enabled(), commonWorker, compute, registration, cfg)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable transaction scheduler process")

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(txnSchedulerAlgorithm.Flags)
}
