package common

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	cfg      *RuntimeHostConfig
	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	runtime host.Runtime
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.Runtime, protocol.Notifier, error) {
	rt, err := n.factory.GetRuntime().RegistryDescriptor(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get runtime registry descriptor: %w", err)
	}

	provisioner, ok := n.cfg.Provisioners[rt.TEEHardware]
	if !ok {
		return nil, nil, fmt.Errorf("no provisioner suitable for TEE hardware '%s'", rt.TEEHardware)
	}

	// Get a copy of the configuration template for the given runtime and apply updates.
	cfg, ok := n.cfg.Runtimes[rt.ID]
	if !ok {
		return nil, nil, fmt.Errorf("missing runtime host configuration for runtime '%s'", rt.ID)
	}
	cfg.MessageHandler = n.factory.NewRuntimeHostHandler()

	// Provision the runtime.
	prt, err := provisioner.NewRuntime(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision runtime: %w", err)
	}
	notifier := n.factory.NewNotifier(ctx, prt)

	n.Lock()
	n.runtime = prt
	n.notifier = notifier
	n.Unlock()

	return prt, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.Runtime {
	n.Lock()
	rt := n.runtime
	n.Unlock()
	return rt
}

// RuntimeHostHandlerFactory is an interface that can be used to create new runtime handlers and
// notifiers when provisioning hosted runtimes.
type RuntimeHostHandlerFactory interface {
	// GetRuntime returns the registered runtime for which a runtime host handler is to be created.
	GetRuntime() runtimeRegistry.Runtime

	// NewRuntimeHostHandler creates a new runtime host handler.
	NewRuntimeHostHandler() protocol.Handler

	// NewNotifier creates a new runtime host notifier.
	NewNotifier(ctx context.Context, host host.Runtime) protocol.Notifier
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(cfg *RuntimeHostConfig, factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("runtime host not configured")
	}

	return &RuntimeHostNode{
		cfg:     cfg,
		factory: factory,
	}, nil
}
