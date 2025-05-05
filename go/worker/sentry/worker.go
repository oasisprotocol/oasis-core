package sentry

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
)

// Enabled returns true if Sentry worker is enabled.
func Enabled() bool {
	return config.GlobalConfig.Sentry.Enabled
}

// Worker is a sentry node worker providing its address(es) to other nodes and
// enabling them to hide their real address(es).
type Worker struct {
	enabled bool

	sentry api.Backend

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

	// Stop the gRPC server when the worker quits.
	go func() {
		<-w.quitCh

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

	w.grpcServer.Cleanup()
}

// New creates a new sentry worker.
func New(sentry api.Backend, identity *identity.Identity) (*Worker, error) {
	w := &Worker{
		enabled: Enabled(),
		sentry:  sentry,
		quitCh:  make(chan struct{}),
		logger:  logging.GetLogger("worker/sentry"),
	}

	if w.enabled {
		peerPubkeyAuth := auth.NewPeerPubkeyAuthenticator()
		for _, pubkey := range config.GlobalConfig.Sentry.Control.AuthorizedPubkeys {
			var pk signature.PublicKey
			if err := pk.UnmarshalText([]byte(pubkey)); err != nil {
				return nil, fmt.Errorf("worker/sentry: failed unmarshalling upstream public key: %s: %w", pubkey, err)
			}
			peerPubkeyAuth.AllowPeerPublicKey(pk)
		}
		grpcServer, err := grpc.NewServer(&grpc.ServerConfig{
			Name:     "sentry",
			Port:     config.GlobalConfig.Sentry.Control.Port,
			Identity: identity,
			AuthFunc: peerPubkeyAuth.AuthFunc,
		})
		if err != nil {
			return nil, fmt.Errorf("worker/sentry: failed to create a new gRPC server: %w", err)
		}
		w.grpcServer = grpcServer
		// Initialize and register the sentry gRPC service.
		api.RegisterService(w.grpcServer.Server(), sentry)
	}

	return w, nil
}
