package txnscheduler

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/compute"
	"github.com/oasislabs/oasis-core/go/worker/registration"
	txnSchedulerAlgorithm "github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm"
)

const (
	// CfgWorkerEnabled enables the tx scheduler worker.
	CfgWorkerEnabled = "worker.txnscheduler.enabled"

	cfgFlushTimeout = "worker.txnscheduler.flush_timeout"
	// XXX: algorithm should eventually become a consensus parameter, as all nodes should use
	// the same algorithm.
	cfgAlgorithm = "worker.txnscheduler.algorithm"
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
	registration *registration.Registration,
) (*Worker, error) {
	// Setup runtimes.
	var runtimes []RuntimeConfig

	for _, runtimeID := range commonWorker.GetConfig().Runtimes {
		runtimes = append(runtimes, RuntimeConfig{
			ID: runtimeID,
		})
	}

	txAlgorithm, err := txnSchedulerAlgorithm.New(viper.GetString(cfgAlgorithm))
	if err != nil {
		return nil, err
	}

	flushTimeout := viper.GetDuration(cfgFlushTimeout)
	cfg := Config{
		Algorithm:    txAlgorithm,
		FlushTimeout: flushTimeout,
		Runtimes:     runtimes,
	}

	return newWorker(Enabled(), commonWorker, compute, registration, cfg)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable transaction scheduler process")

	Flags.String(cfgAlgorithm, "batching", "Transaction scheduling algorithm")
	Flags.Duration(cfgFlushTimeout, 1*time.Second, "Maximum amount of time to wait for a scheduled batch")

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(txnSchedulerAlgorithm.Flags)
}
