package sentry

import (
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
	workerGrpcSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry/grpc"
)

const (
	// CfgEnabled enables the sentry worker.
	CfgEnabled = "worker.sentry.enabled"
	// CfgControlPort configures the sentry worker's control port.
	CfgControlPort = "worker.sentry.control.port"
	// CfgAuthorizedControlPubkeys configures the public keys of upstream nodes
	// that are allowed to connect to the sentry control endpoint.
	CfgAuthorizedControlPubkeys = "worker.sentry.control.authorized_pubkey"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled returns true if Sentry worker is enabled.
func Enabled() bool {
	return viper.GetBool(CfgEnabled)
}

// Worker is a sentry node worker providing its address(es) to other nodes and
// enabling them to hide their real address(es).
type Worker struct {
	enabled bool

	grpcWorker *workerGrpcSentry.Worker

	backend api.LocalBackend

	grpcServer *grpc.Server

	quitCh chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "sentry worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting sentry worker as it is disabled")

		return nil
	}

	// Start the sentry gRPC server.
	if err := w.grpcServer.Start(); err != nil {
		w.logger.Error("failed to start sentry gRPC server",
			"err", err,
		)
		return err
	}

	// Start the sentry gRPC worker.
	if err := w.grpcWorker.Start(); err != nil {
		return err
	}

	// Stop the gRPC server when the worker quits.
	go func() {
		defer close(w.quitCh)

		<-w.grpcWorker.Quit()
		w.logger.Debug("sentry gRPC worker quit, stopping sentry gRPC server")
		w.grpcServer.Stop()
	}()

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	w.grpcWorker.Stop()
	// The gRPC server will terminate once the worker quits.
}

// Enabled returns true if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
	if !w.enabled {
		return
	}

	w.grpcWorker.Cleanup()
	w.grpcServer.Cleanup()
}

// New creates a new sentry worker.
func New(backend api.LocalBackend, identity *identity.Identity) (*Worker, error) {
	w := &Worker{
		enabled: Enabled(),
		backend: backend,
		quitCh:  make(chan struct{}),
		logger:  logging.GetLogger("worker/sentry"),
	}

	if w.enabled {
		peerPubkeyAuth := auth.NewPeerPubkeyAuthenticator()
		for _, pubkey := range viper.GetStringSlice(CfgAuthorizedControlPubkeys) {
			var pk signature.PublicKey
			if err := pk.UnmarshalText([]byte(pubkey)); err != nil {
				return nil, fmt.Errorf("worker/sentry: failed unmarshalling upstream public key: %s: %w", pubkey, err)
			}
			peerPubkeyAuth.AllowPeerPublicKey(pk)
		}
		grpcServer, err := grpc.NewServer(&grpc.ServerConfig{
			Name:     "sentry",
			Port:     uint16(viper.GetInt(CfgControlPort)),
			Identity: identity,
			AuthFunc: peerPubkeyAuth.AuthFunc,
		})
		if err != nil {
			return nil, fmt.Errorf("worker/sentry: failed to create a new gRPC server: %w", err)
		}
		w.grpcServer = grpcServer
		// Initialize and register the sentry gRPC service.
		api.RegisterService(w.grpcServer.Server(), backend)
	}

	// Initialize the sentry grpc worker.
	sentryGrpcWorker, err := workerGrpcSentry.New(backend, identity)
	if err != nil {
		return nil, fmt.Errorf("worker/sentry: failed to create a new sentry grpc worker: %w", err)
	}
	w.grpcWorker = sentryGrpcWorker

	return w, nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable Sentry worker (NOTE: This should only be enabled on Sentry nodes.)")
	Flags.Uint16(CfgControlPort, 9009, "Sentry worker's gRPC server port (NOTE: This should only be enabled on Sentry nodes.)")
	Flags.StringSlice(CfgAuthorizedControlPubkeys, []string{}, "Public keys of upstream nodes that are allowed to connect to sentry control endpoint.")
	Flags.AddFlagSet(workerGrpcSentry.Flags)

	_ = viper.BindPFlags(Flags)
}
