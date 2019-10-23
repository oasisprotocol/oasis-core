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
	CfgWorkerEnabled = "worker.txnscheduler.enabled"
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

	// Fetch config from scheduler backend.
	genesis := commonWorker.GenesisDoc.RootHash.TransactionScheduler

	txAlgorithm, err := txnSchedulerAlgorithm.New(
		genesis.Algorithm,
		genesis.MaxBatchSize,
		genesis.MaxBatchSizeBytes,
	)
	if err != nil {
		return nil, err
	}

	cfg := Config{
		Algorithm:    txAlgorithm,
		FlushTimeout: genesis.BatchFlushTimeout,
		Runtimes:     runtimes,
	}

	return newWorker(Enabled(), commonWorker, compute, registration, cfg)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable transaction scheduler process")

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(txnSchedulerAlgorithm.Flags)
}
