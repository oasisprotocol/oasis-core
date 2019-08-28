package merge

import (
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/merge/committee"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgWorkerEnabled                = "worker.merge.enabled"
	cfgStorageCommitTimeout         = "worker.merge.storage_commit_timeout"
	cfgByzantineInjectDiscrepancies = "worker.merge.byzantine.inject_discrepancies"
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
	registration *registration.Registration,
) (*Worker, error) {
	cfg := Config{
		Committee: committee.Config{
			StorageCommitTimeout:         viper.GetDuration(cfgStorageCommitTimeout),
			ByzantineInjectDiscrepancies: viper.GetBool(cfgByzantineInjectDiscrepancies),
		},
	}

	return newWorker(Enabled(), commonWorker, registration, cfg)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(Flags)
	}
}

func init() {
	Flags.Bool(cfgWorkerEnabled, false, "Enable merge worker process")
	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	Flags.Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies")
	_ = Flags.MarkHidden(cfgByzantineInjectDiscrepancies)

	_ = viper.BindPFlags(Flags)
}
