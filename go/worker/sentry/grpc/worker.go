package grpc

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/auth"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	policyAPI "github.com/oasislabs/oasis-core/go/common/grpc/policy/api"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/service"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var _ service.BackgroundService = (*Worker)(nil)

// Worker is a gRPC sentry node worker proxying gRPC requests to upstream node.
type Worker struct { // nolint: maligned
	sync.RWMutex

	enabled bool

	ctx       context.Context
	cancelCtx context.CancelFunc

	initCh chan struct{}
	stopCh chan struct{}
	quitCh chan struct{}

	logger *logging.Logger

	policyWatcher policyAPI.PolicyWatcherClient
	// Per service policy checkers.
	grpcPolicyCheckers map[cmnGrpc.ServiceName]*policy.DynamicRuntimePolicyChecker

	registryClient registry.Backend

	*upstreamConn

	grpc     *cmnGrpc.Server
	identity *identity.Identity

	// Set to true when quitting if the master worker shouldn't quit,
	// but re-init due to changed TLS certificates on the upstream node.
	AmQuittingBecauseTLSCertsHaveRotated bool
}

type upstreamConn struct {
	// ID of the upstream node.
	nodeID signature.PublicKey
	// TLS certificates for the upstream node.
	certs [][]byte
	// Client connection to the upstream node.
	conn *grpc.ClientConn
	// Registry client connection.
	registryClientConn *grpc.ClientConn
	// Cleanup callback for the manual resolver.
	resolverCleanupCb func()
}

func (g *Worker) authFunction() auth.AuthenticationFunction {
	return func(ctx context.Context,
		fullMethodName string,
		req interface{}) error {

		serviceName := cmnGrpc.ServiceNameFromMethod(fullMethodName)
		if serviceName == "" {
			g.logger.Error("error getting service name from method",
				"method_name", fullMethodName,
			)
			return status.Errorf(codes.PermissionDenied, fmt.Sprintf("invalid service in method: %s", fullMethodName))
		}

		// Get method request type.
		methodDesc, err := cmnGrpc.GetRegisteredMethod(fullMethodName)
		if err != nil {
			g.logger.Error("error getting registered gRPC method",
				"method_name", fullMethodName,
				"err", err,
			)
			return status.Errorf(codes.PermissionDenied, fmt.Sprintf("unknown method: %s", fullMethodName))
		}

		g.RLock()
		defer g.RUnlock()

		// Ensure policy checker for the service exists. This needs to be done
		// before checking if method is access controlled as otherwise the
		// proxy would allow and propagate request for all registered methods
		// without acesss control (even those not implemented by the upstream).
		// XXX: This means that the proxy will reject requests to upstream
		// services that do not provide at least a single policy checker.
		// This is not the case in either of currently supported upstreams
		// (storage and keymanager).
		p, ok := g.grpcPolicyCheckers[serviceName]
		if !ok {
			g.logger.Error("no policy checker defined for service",
				"service_name", serviceName,
				"policy_checkers", g.grpcPolicyCheckers,
			)
			return status.Errorf(codes.PermissionDenied, "not allowed")
		}

		if !methodDesc.IsAccessControlled(req) {
			// No access controll, allow.
			return nil
		}

		// Proxy defers unmarshaling.
		rawCBOR, ok := req.(*cbor.RawMessage)
		if !ok {
			g.logger.Error("invalid proxy request type, expected *cbor.RawMessage",
				"request", req,
				"request_type", fmt.Sprintf("%T", req),
			)
			return status.Errorf(codes.PermissionDenied, "invalid request")
		}

		// Unmarshal into correct type.
		request, err := methodDesc.UnmarshalRawMessage(rawCBOR)
		if err != nil {
			g.logger.Error("error unamrshaling raw request",
				"err", err,
				"raw", rawCBOR,
			)
			return status.Errorf(codes.PermissionDenied, "invalid request")
		}

		// Extract namespace.
		namespace, err := methodDesc.ExtractNamespace(request)
		if err != nil {
			g.logger.Error("error extracting namespace from request",
				"err", err,
				"request", request,
			)
			return status.Errorf(codes.PermissionDenied, "invalid request")
		}

		return p.CheckAccessAllowed(ctx, accessctl.Action(fullMethodName), namespace)
	}
}

func (g *Worker) updatePolicies(p policyAPI.ServicePolicies) {
	g.logger.Debug("updating policies",
		"policy", p,
	)

	g.Lock()
	defer g.Unlock()

	g.grpcPolicyCheckers[p.Service] = policy.NewDynamicRuntimePolicyChecker(p.Service, nil)
	for namespace, policy := range p.AccessPolicies {
		g.grpcPolicyCheckers[p.Service].SetAccessPolicy(policy, namespace)
	}
}

// Returns true if we need to restart.
func (g *Worker) checkUpstreamNodeTLSCerts(nodeEvent *registry.NodeEvent) bool {
	if !nodeEvent.IsRegistration {
		return false
	}

	// Check if it's our upstream node.
	if !nodeEvent.Node.ID.Equal(g.nodeID) {
		return false
	}

	// XXX: Not sure if certificates are guaranteed to be sorted,
	// so we do this slow lookup to be sure.
	var numCertMatches uint
	for _, cert1 := range g.certs {
		for _, addr2 := range nodeEvent.Node.Committee.Addresses {
			if bytes.Equal(cert1, addr2.Certificate) {
				numCertMatches++
			}
		}
	}

	// If the number of matching certificates differs, they were rotated,
	// so a reconnect is required.
	return numCertMatches != uint(len(g.certs))
}

func (g *Worker) worker() {
	defer close(g.quitCh)
	defer (g.cancelCtx)()

	// Initialize policy watcher.
	g.policyWatcher = policyAPI.NewPolicyWatcherClient(g.conn)
	ch, sub, err := g.policyWatcher.WatchPolicies(g.ctx)
	if err != nil {
		g.logger.Error("failed to watch policies",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Initialize registry watcher.
	g.registryClient = registry.NewRegistryClient(g.registryClientConn)
	regCh, regSub, regErr := g.registryClient.WatchNodes(g.ctx)
	if regErr != nil {
		g.logger.Error("failed to watch registry nodes",
			"err", regErr,
		)
		return
	}
	defer regSub.Close()

	// Initialization complete.
	close(g.initCh)

	// Watch policies and registry.
	for {
		select {
		case nodeEvent, ok := <-regCh:
			if !ok {
				g.logger.Error("WatchNodes stream closed")
				return
			}

			if g.checkUpstreamNodeTLSCerts(nodeEvent) {
				// Upstream node TLS certificates changed, restart is needed.
				g.AmQuittingBecauseTLSCertsHaveRotated = true
				return
			}
		case p, ok := <-ch:
			if !ok {
				g.logger.Error("WatchPolicies stream closed")
				return
			}

			g.updatePolicies(p)
		case <-g.stopCh:
			return
		case <-g.grpc.Quit():
			return
		}
	}
}

// Initialized returns a channel that will be closed when the worker initializes.
func (g *Worker) Initialized() <-chan struct{} {
	return g.initCh
}

// Start starts the worker.
func (g *Worker) Start() error {
	if !g.enabled {
		g.logger.Info("not starting gRPC sentry worker as it is disabled")
		return nil
	}

	g.logger.Info("Starting gRPC sentry worker")

	// Start the gRPC sentry server.
	if err := g.grpc.Start(); err != nil {
		g.logger.Error("failed to start external grpc sentry gRPC server",
			"err", err,
		)
		return err
	}

	// Start the worker.
	go g.worker()

	return nil
}

// Name returns the service name.
func (g *Worker) Name() string {
	return "gRPC sentry worker"
}

// Stop halts the worker.
func (g *Worker) Stop() {
	if !g.enabled {
		close(g.stopCh)
		return
	}

	g.grpc.Stop()
	close(g.stopCh)
}

// Cleanup performs the service specific post-termination cleanup.
func (g *Worker) Cleanup() {
	if !g.enabled {
		return
	}
	g.grpc.Cleanup()
}

// Quit returns a channel that will be closed when the service terminates.
func (g *Worker) Quit() <-chan struct{} {
	return g.quitCh
}
