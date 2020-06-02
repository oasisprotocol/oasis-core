// Package consensus implements publicly accessible consensus services.
package consensus

import (
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	// CfgWorkerEnabled enables the consensus RPC services worker.
	CfgWorkerEnabled = "worker.consensusrpc.enabled"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Worker is a worker providing publicly accessible consensus services.
//
// Currently this only exposes the consensus light client service.
type Worker struct {
	enabled bool

	commonWorker *workerCommon.Worker

	quitCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "public consensus RPC services worker"
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

// Start starts the worker.
func (w *Worker) Start() error {
	if w.enabled {
		w.logger.Info("starting public consensus RPC services worker")
	}
	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	close(w.quitCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
}

// New creates a new public consensus services worker.
func New(commonWorker *workerCommon.Worker, registration *registration.Worker) (*Worker, error) {
	w := &Worker{
		enabled:      Enabled(),
		commonWorker: commonWorker,
		quitCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/consensusrpc"),
	}

	if w.enabled {
		// Register the consensus light client service.
		consensus.RegisterLightService(commonWorker.Grpc.Server(), commonWorker.Consensus)

		// Publish our role to ease discovery for clients.
		rp, err := registration.NewRoleProvider(node.RoleConsensusRPC)
		if err != nil {
			return nil, fmt.Errorf("failed to create role provider: %w", err)
		}

		// The consensus RPC service is available immediately.
		rp.SetAvailable(func(*node.Node) error { return nil })
	}

	return w, nil
}

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgWorkerEnabled)
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable public consensus RPC services worker")

	_ = viper.BindPFlags(Flags)
}
