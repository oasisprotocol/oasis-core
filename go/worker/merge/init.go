package merge

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

const (
	// CfgWorkerEnabled enables the merge worker.
	CfgWorkerEnabled = "worker.merge.enabled"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

// New creates a new worker.
func New(commonWorker *workerCommon.Worker, registration *registration.Worker) (*Worker, error) {
	return newWorker(Enabled(), commonWorker, registration)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable merge worker process")

	_ = viper.BindPFlags(Flags)
}
