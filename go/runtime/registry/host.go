package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

const (
	// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
	notifyTimeout = 10 * time.Second

	// retryInterval is the time interval used between failed key manager updates.
	retryInterval = time.Second

	// minAttestationInterval is the minimum attestation interval.
	minAttestationInterval = 5 * time.Minute
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	sync.Mutex

	factory  RuntimeHostHandlerFactory
	notifier protocol.Notifier

	agg           *multi.Aggregate
	runtime       host.RichRuntime
	runtimeNotify chan struct{}
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	return &RuntimeHostNode{
		factory:       factory,
		runtimeNotify: make(chan struct{}),
	}, nil
}

// ProvisionHostedRuntime provisions the configured runtime.
//
// This method may return before the runtime is fully provisioned. The returned runtime will not be
// started automatically, you must call Start explicitly.
func (n *RuntimeHostNode) ProvisionHostedRuntime(ctx context.Context) (host.RichRuntime, protocol.Notifier, error) {
	runtime := n.factory.GetRuntime()
	cfgs := runtime.HostConfig()
	provisioner := runtime.HostProvisioner()
	if cfgs == nil || provisioner == nil {
		return nil, nil, fmt.Errorf("runtime provisioner is not available")
	}

	// Provision the handler that implements the host RHP methods.
	msgHandler := n.factory.NewRuntimeHostHandler()

	rts := make(map[version.Version]host.Runtime)
	for version, cfg := range cfgs {
		rtCfg := *cfg
		rtCfg.MessageHandler = msgHandler

		// Provision the runtime.
		var err error
		if rts[version], err = composite.NewHost(rtCfg, provisioner); err != nil {
			return nil, nil, fmt.Errorf("failed to provision runtime version %s: %w", version, err)
		}
	}

	agg, err := multi.New(runtime.ID(), rts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to provision aggregate runtime: %w", err)
	}

	notifier := n.factory.NewRuntimeHostNotifier(ctx, agg)
	rr := host.NewRichRuntime(agg)

	n.Lock()
	n.agg = agg.(*multi.Aggregate)
	n.runtime = rr
	n.notifier = notifier
	n.Unlock()

	close(n.runtimeNotify)

	return rr, notifier, nil
}

// GetHostedRuntime returns the provisioned hosted runtime (if any).
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	n.Lock()
	defer n.Unlock()

	return n.runtime
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

// GetHostedRuntimeActiveVersion returns the version of the active runtime.
func (n *RuntimeHostNode) GetHostedRuntimeActiveVersion() (*version.Version, error) {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return nil, fmt.Errorf("runtime not available")
	}

	return agg.GetActiveVersion()
}

// GetHostedRuntimeCapabilityTEE returns the CapabilityTEE for the active runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEE() (*node.CapabilityTEE, error) {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return nil, fmt.Errorf("runtime not available")
	}

	return agg.GetCapabilityTEE()
}

// GetHostedRuntimeCapabilityTEEForVersion returns the CapabilityTEE for a specific runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEEForVersion(version version.Version) (*node.CapabilityTEE, error) {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return nil, fmt.Errorf("runtime not available")
	}

	rt, err := agg.GetVersion(version)
	if err != nil {
		return nil, err
	}
	return rt.GetCapabilityTEE()
}

// SetHostedRuntimeVersion sets the currently active and next versions for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(active version.Version, next *version.Version) error {
	n.Lock()
	agg := n.agg
	n.Unlock()

	if agg == nil {
		return fmt.Errorf("runtime not available")
	}

	return agg.SetVersion(active, next)
}
