package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentracing/opentracing-go"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("endpoint not supported")
)

type clientHost struct {
	*runtimeRegistry.RuntimeHostNode

	runtime   runtimeRegistry.Runtime
	consensus consensus.Backend

	stopCh chan struct{}
	quitCh chan struct{}

	logger *logging.Logger
}

// Start starts the client host.
func (h *clientHost) Start() error {
	go h.worker()
	return nil
}

// Stop asks the client host to stop.
func (h *clientHost) Stop() {
	close(h.stopCh)
}

// Quit returns the channel which will signal when the client host has quit.
func (h *clientHost) Quit() <-chan struct{} {
	return h.quitCh
}

// Implements runtimeRegistry.RuntimeHostHandlerFactory.
func (h *clientHost) GetRuntime() runtimeRegistry.Runtime {
	return h.runtime
}

// Implements runtimeRegistry.RuntimeHostHandlerFactory.
func (h *clientHost) NewRuntimeHostHandler() protocol.Handler {
	return h
}

// Implements runtimeRegistry.RuntimeHostHandlerFactory.
func (h *clientHost) NewNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return nil
}

// Implements protocol.Handler.
func (h *clientHost) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	// Storage.
	case body.HostStorageSyncRequest != nil:
		rq := body.HostStorageSyncRequest
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.Sync")
		defer span.Finish()

		var rs syncer.ReadSyncer
		switch rq.Endpoint {
		case protocol.HostStorageEndpointRuntime:
			// Runtime storage.
			rs = h.runtime.Storage()
		case protocol.HostStorageEndpointConsensus:
			// Consensus state storage.
			rs = h.consensus.State()
		default:
			return nil, errEndpointNotSupported
		}

		var rsp *storage.ProofResponse
		var err error
		switch {
		case rq.SyncGet != nil:
			rsp, err = rs.SyncGet(sctx, rq.SyncGet)
		case rq.SyncGetPrefixes != nil:
			rsp, err = rs.SyncGetPrefixes(sctx, rq.SyncGetPrefixes)
		case rq.SyncIterate != nil:
			rsp, err = rs.SyncIterate(sctx, rq.SyncIterate)
		default:
			return nil, errMethodNotSupported
		}
		if err != nil {
			return nil, err
		}

		return &protocol.Body{HostStorageSyncResponse: &protocol.HostStorageSyncResponse{ProofResponse: rsp}}, nil
	// Local storage.
	case body.HostLocalStorageGetRequest != nil:
		value, err := h.runtime.LocalStorage().Get(body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	case body.HostLocalStorageSetRequest != nil:
		if err := h.runtime.LocalStorage().Set(body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	default:
		return nil, errMethodNotSupported
	}
}

func (h *clientHost) worker() {
	defer close(h.quitCh)

	// Wait for consensus sync.
	select {
	case <-h.consensus.Synced():
	case <-h.stopCh:
		return
	}

	// Start hosted runtime provisioning.
	hrt, _, err := h.ProvisionHostedRuntime(context.Background())
	switch {
	case err == nil:
	default:
		h.logger.Error("failed to provision hosted runtime",
			"err", err,
		)
		return
	}

	// Start the runtime.
	if err = hrt.Start(); err != nil {
		h.logger.Error("failed to start hosted runtime",
			"err", err,
		)
		return
	}

	// Wait for the stop signal.
	<-h.stopCh

	// Ask the runtime to stop as well.
	hrt.Stop()
}

func newClientHost(runtime runtimeRegistry.Runtime, consensus consensus.Backend) (*clientHost, error) {
	host := &clientHost{
		runtime:   runtime,
		consensus: consensus,
		stopCh:    make(chan struct{}),
		quitCh:    make(chan struct{}),
		logger:    logging.GetLogger("runtime/client/host"),
	}

	var err error
	host.RuntimeHostNode, err = runtimeRegistry.NewRuntimeHostNode(host)
	if err != nil {
		return nil, fmt.Errorf("failed to create runtime host helper: %w", err)
	}

	return host, nil
}
