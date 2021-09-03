package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanagerClient "github.com/oasisprotocol/oasis-core/go/keymanager/client"
	keymanagerClientApi "github.com/oasisprotocol/oasis-core/go/keymanager/client/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

type clientHost struct {
	sync.Mutex

	*runtimeRegistry.RuntimeHostNode

	runtime          runtimeRegistry.Runtime
	consensus        consensus.Backend
	keyManagerClient keymanagerClientApi.Client

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
	return runtimeRegistry.NewRuntimeHostHandler(h, h.runtime, h.consensus)
}

// Implements runtimeRegistry.RuntimeHostHandlerFactory.
func (h *clientHost) NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(ctx, h.runtime, host, h.consensus)
}

// Implements runtimeRegistry.RuntimeHostHandlerEnvironment.
func (h *clientHost) GetCurrentBlock(ctx context.Context) (*block.Block, error) {
	return nil, fmt.Errorf("not available")
}

// Implements runtimeRegistry.RuntimeHostHandlerEnvironment.
func (h *clientHost) GetKeyManagerClient(ctx context.Context) (keymanagerClientApi.Client, error) {
	h.Lock()
	defer h.Unlock()

	// If any existing key manager client is available, just reuse it.
	if h.keyManagerClient != nil {
		return h.keyManagerClient, nil
	}

	// Otherwise create a fresh one on demand.
	cliCtx, cancel := context.WithCancel(context.Background())
	go func() {
		<-h.stopCh
		cancel()
	}()

	var err error
	h.keyManagerClient, err = keymanagerClient.New(cliCtx, h.runtime, h.consensus, nil)
	if err != nil {
		h.logger.Error("failed to create key manager client instance",
			"err", err,
		)
		return nil, fmt.Errorf("failed to create key manager client: %w", err)
	}
	return h.keyManagerClient, nil
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
