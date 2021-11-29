package executor

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	cfgMaxTxPoolSize       = "worker.executor.schedule_max_tx_pool_size"
	cfgScheduleTxCacheSize = "worker.executor.schedule_tx_cache_size"
	cfgCheckTxMaxBatchSize = "worker.executor.check_tx_max_batch_size"
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
		commonWorker,
		registration,
		viper.GetUint64(cfgMaxTxPoolSize),
		viper.GetUint64(cfgScheduleTxCacheSize),
		viper.GetUint64(cfgCheckTxMaxBatchSize),
	)
}

func init() {
	Flags.Uint64(cfgMaxTxPoolSize, 10_000, "Maximum size of the scheduling transaction pool")
	Flags.Uint64(cfgScheduleTxCacheSize, 10_000, "Cache size of recently scheduled transactions to prevent re-scheduling")
	Flags.Uint64(cfgCheckTxMaxBatchSize, 10_000, "Maximum check tx batch size")

	_ = viper.BindPFlags(Flags)
}
