package registry

import (
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// RuntimeHostNode provides methods for nodes that need to host runtimes.
type RuntimeHostNode struct {
	mu sync.Mutex

	host *composite.Host
	rr   host.RichRuntime

	runtime     Runtime
	notifier    protocol.Notifier
	handler     host.RuntimeHandler
	provisioner host.Provisioner

	rofls map[component.ID]version.Version
}

// NewRuntimeHostNode creates a new runtime host node.
func NewRuntimeHostNode(factory RuntimeHostHandlerFactory) (*RuntimeHostNode, error) {
	runtime := factory.GetRuntime()
	h := composite.NewHost(runtime.ID())
	rr := host.NewRichRuntime(h)

	notifier := factory.NewRuntimeHostNotifier(h)
	handler := factory.NewRuntimeHostHandler()
	provisioner := runtime.HostProvisioner()

	return &RuntimeHostNode{
		host:        h,
		rr:          rr,
		runtime:     runtime,
		notifier:    notifier,
		handler:     handler,
		provisioner: provisioner,
		rofls:       make(map[component.ID]version.Version),
	}, nil
}

// ProvisionHostedRuntimeComponent provisions the given runtime component.
func (n *RuntimeHostNode) ProvisionHostedRuntimeComponent(comp *bundle.ExplodedComponent) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.isComponentWanted(comp) {
		return nil
	}
	if n.host.HasVersion(comp.ID(), comp.Version) {
		return nil
	}

	handler, err := n.createMessageHandler(comp)
	if err != nil {
		return err
	}

	cfg := host.Config{
		ID:             n.runtime.ID(),
		Component:      comp,
		MessageHandler: handler,
		LocalConfig:    getLocalConfig(n.runtime.ID()),
	}

	rt, err := n.provisioner.NewRuntime(cfg)
	if err != nil {
		return fmt.Errorf("failed to provision runtime component %s version %s: %w", comp.ID(), comp.Version, err)
	}

	if err = handler.AttachRuntime(comp.ID(), rt); err != nil {
		return fmt.Errorf("failed to attach runtime host to handler: %w", err)
	}

	if err := n.host.AddVersion(comp.ID(), comp.Version, rt); err != nil {
		return fmt.Errorf("failed to add runtime component %s version %s to composite: %w", comp.ID(), comp.Version, err)
	}

	if comp.Kind == component.ROFL && comp.Version.Cmp(n.rofls[comp.ID()]) >= 0 {
		n.rofls[comp.ID()] = comp.Version
	}

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

// GetHostedRuntimeActiveVersion returns the version of the active runtime.
func (n *RuntimeHostNode) GetHostedRuntimeActiveVersion() (*version.Version, error) {
	return n.host.GetActiveVersion()
}

// GetHostedRuntimeCapabilityTEE returns the CapabilityTEE for the active runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEE() (*node.CapabilityTEE, error) {
	return n.host.GetCapabilityTEE()
}

// GetHostedRuntimeCapabilityTEEForVersion returns the CapabilityTEE for a specific runtime version.
//
// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
// inside a TEE.
func (n *RuntimeHostNode) GetHostedRuntimeCapabilityTEEForVersion(version version.Version) (*node.CapabilityTEE, error) {
	comp, ok := n.host.Component(component.ID_RONL)
	if !ok {
		return nil, fmt.Errorf("failed to get RONL component runtime host")
	}
	rt, err := comp.Version(version)
	if err != nil {
		return nil, err
	}
	return rt.GetCapabilityTEE()
}

// SetHostedRuntimeVersion sets the currently active and next versions for the hosted runtime.
func (n *RuntimeHostNode) SetHostedRuntimeVersion(active *version.Version, next *version.Version) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for id, comp := range n.host.Components() {
		latest, ok := n.rofls[id]
		if !ok {
			comp.SetVersion(active, next)
			continue
		}

		// ROFL components should start when the RONL component starts and
		// should upgrade immediately when a new version becomes available.
		switch {
		case active == nil && next == nil:
			comp.SetVersion(nil, nil)
		case active == nil && next != nil:
			comp.SetVersion(nil, &latest)
		default:
			comp.SetVersion(&latest, nil)
		}
	}
}

func (n *RuntimeHostNode) createMessageHandler(comp *bundle.ExplodedComponent) (host.RuntimeHandler, error) {
	switch comp.Kind {
	case component.RONL:
		return n.handler, nil
	case component.ROFL:
		handler, err := n.handler.NewSubHandler(comp.ID())
		if err != nil {
			return nil, fmt.Errorf("failed to create sub-handler: %w", err)
		}
		ronl, ok := n.host.Component(component.ID_RONL)
		if !ok {
			return nil, fmt.Errorf("failed to get RONL component runtime host")
		}
		if err = handler.AttachRuntime(component.ID_RONL, ronl); err != nil {
			return nil, fmt.Errorf("failed to attach runtime host to handler: %w", err)
		}
		return handler, nil
	default:
		return nil, fmt.Errorf("failed to create handler for %s", comp.Kind)
	}
}

func (n *RuntimeHostNode) isComponentWanted(comp *bundle.ExplodedComponent) bool {
	// Always allow RONL component.
	if comp.ID().IsRONL() {
		return true
	}

	// Node configuration overrides all other settings.
	if compCfg, ok := config.GlobalConfig.Runtime.GetComponent(n.runtime.ID(), comp.ID()); ok {
		return !compCfg.Disabled
	}

	// Detached components are explicit and they should be enabled by default.
	if comp.Detached {
		return true
	}

	// On non-compute nodes, assume all components are disabled by default.
	if config.GlobalConfig.Mode != config.ModeCompute {
		return false
	}

	// By default honor the status of the component itself.
	return !comp.Disabled
}
