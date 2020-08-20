package executor

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/compute"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	// CfgScheduleCheckTxEnabled enables checking each transaction before
	// scheduling it.
	CfgScheduleCheckTxEnabled = "worker.executor.schedule_check_tx.enabled"

	cfgMaxQueueSize = "worker.executor.schedule_max_queue_size"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New creates a new executor worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	registration *registration.Worker,
) (*Worker, error) {
	return newWorker(
		dataDir,
		compute.Enabled(),
		commonWorker,
		registration,
		viper.GetBool(CfgScheduleCheckTxEnabled),
		viper.GetUint64(cfgMaxQueueSize),
	)
}

func init() {
	Flags.Bool(CfgScheduleCheckTxEnabled, false, "Enable checking transactions before scheduling them")
	Flags.Uint64(cfgMaxQueueSize, 10000, "Maximum size of the scheduling queue")

	_ = viper.BindPFlags(Flags)
}
