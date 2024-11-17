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
	agg *multi.Aggregate
	rr  host.RichRuntime

	runtime Runtime

	notifier protocol.Notifier
	handler  host.RuntimeHandler

	provisioner host.Provisioner

	runtimeNotify     chan struct{}
	runtimeNotifyOnce sync.Once
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	runtime := factory.GetRuntime()
	agg := multi.New(runtime.ID())
	rr := host.NewRichRuntime(agg)

	notifier := factory.NewRuntimeHostNotifier(agg)
	handler := factory.NewRuntimeHostHandler()
	provisioner := runtime.HostProvisioner()

	return &RuntimeHostNode{
		agg:           agg,
		rr:            rr,
		runtime:       runtime,
		notifier:      notifier,
		handler:       handler,
		provisioner:   provisioner,
		runtimeNotify: make(chan struct{}),
	}, nil
}

// ProvisionHostedRuntimeVersion provisions the configured runtime version.
func (n *RuntimeHostNode) ProvisionHostedRuntimeVersion(version version.Version) error {
	cfg := n.runtime.HostConfig(version)
	if cfg == nil {
		return fmt.Errorf("runtime version %s not found", version)
	}

	rtCfg := *cfg
	rtCfg.MessageHandler = n.handler

	rt, err := composite.NewHost(rtCfg, n.provisioner)
	if err != nil {
		return fmt.Errorf("failed to provision runtime version %s: %w", version, err)
	}

	if err := n.agg.AddVersion(rt, version); err != nil {
		return fmt.Errorf("failed to add runtime version to aggregate %s: %w", version, err)
	}

	n.runtimeNotifyOnce.Do(func() {
		close(n.runtimeNotify)
	})

	return nil
}

// GetHostedRuntime returns the hosted runtime.
func (n *RuntimeHostNode) GetHostedRuntime() host.RichRuntime {
	return n.rr
}

// GetRuntimeHostNotifier returns the runtime host notifier.
func (n *RuntimeHostNode) GetRuntimeHostNotifier() protocol.Notifier {
	return n.notifier
}

// WaitHostedRuntime waits for the hosted runtime to be provisioned.
func (n *RuntimeHostNode) WaitHostedRuntime(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.runtimeNotify:
	}

	return nil
}

// GetHostedRuntimeActiveVersion returns the version of the active runtime.
func (n *RuntimeHostNode) GetHostedRuntimeActiveVersion() (*version.Version, error) {
	return n.agg.GetActiveVersion()
}

// GetHostedRuntimeCapabilityTEE returns the CapabilityTEE for the active runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEE() (*node.CapabilityTEE, error) {
	return n.agg.GetCapabilityTEE()
}

// GetHostedRuntimeCapabilityTEEForVersion returns the CapabilityTEE for a specific runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEEForVersion(version version.Version) (*node.CapabilityTEE, error) {
	rt, err := n.agg.GetVersion(version)
	if err != nil {
		return nil, err
	}
	return rt.GetCapabilityTEE()
}

// SetHostedRuntimeVersion sets the currently active and next versions for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(active *version.Version, next *version.Version) {
	n.agg.SetVersion(active, next)
}
