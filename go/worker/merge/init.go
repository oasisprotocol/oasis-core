package merge

import (
	"time"

	"github.com/spf13/cobra"
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
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable merge worker process")
		cmd.Flags().Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

		cmd.Flags().Bool(cfgByzantineInjectDiscrepancies, false, "BYZANTINE: Inject discrepancies")
		_ = cmd.Flags().MarkHidden(cfgByzantineInjectDiscrepancies)
	}

	for _, v := range []string{
		cfgWorkerEnabled,
		cfgStorageCommitTimeout,
		cfgByzantineInjectDiscrepancies,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
