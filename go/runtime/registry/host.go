package registry

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	runtime       host.RichRuntime
	runtimeNotify chan struct{}
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.RichRuntime, protocol.Notifier, error) {
	cfg, provisioner, err := n.factory.GetRuntime().Host(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime host: %w", err)
	}
	cfg.MessageHandler = n.factory.NewRuntimeHostHandler()

	// Provision the runtime.
	prt, err := provisioner.NewRuntime(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision runtime: %w", err)
	}
	notifier := n.factory.NewNotifier(ctx, prt)
	rr := host.NewRichRuntime(prt)

	n.Lock()
	n.runtime = rr
	n.notifier = notifier
	n.Unlock()

	close(n.runtimeNotify)

	return rr, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	n.Lock()
	rt := n.runtime
	n.Unlock()
	return rt
}

// WaitHostedRuntime waits for the hosted runtime to be provisioned and returns it.
func (n *RuntimeHostNode) WaitHostedRuntime(ctx context.Context) (host.RichRuntime, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.runtimeNotify:
	}

	return n.GetHostedRuntime(), nil
}

// RuntimeHostHandlerFactory is an interface that can be used to create new runtime handlers and
// notifiers when provisioning hosted runtimes.
type RuntimeHostHandlerFactory interface {
	// GetRuntime returns the registered runtime for which a runtime host handler is to be created.
	GetRuntime() Runtime

	// NewRuntimeHostHandler creates a new runtime host handler.
	NewRuntimeHostHandler() protocol.Handler

	// NewNotifier creates a new runtime host notifier.
	NewNotifier(ctx context.Context, host host.Runtime) protocol.Notifier
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	return &RuntimeHostNode{
		factory:       factory,
		runtimeNotify: make(chan struct{}),
	}, nil
}
