package txnscheduler

import (
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute"
	"github.com/oasislabs/ekiden/go/worker/registration"
	txnSchedulerAlgorithm "github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm"
)

const (
	cfgWorkerEnabled = "worker.txnscheduler.enabled"
	cfgFlushTimeout  = "worker.txnscheduler.flush_timeout"
	// XXX: algorithm should eventually become a consensus parameter, as all nodes should use
	// the same algorithm.
	cfgAlgorithm = "worker.txnscheduler.algorithm"
)

// Flags has our flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(cfgWorkerEnabled)
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(Flags)
	}

	txnSchedulerAlgorithm.RegisterFlags(cmd)
}

func init() {
	Flags.Bool(cfgWorkerEnabled, false, "Enable transaction scheduler process")

	Flags.String(cfgAlgorithm, "batching", "Transaction scheduling algorithm")
	Flags.Duration(cfgFlushTimeout, 1*time.Second, "Maximum amount of time to wait for a scheduled batch")

	_ = viper.BindPFlags(Flags)
}
