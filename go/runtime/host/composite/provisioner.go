package composite

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

type compositeProvisioner struct {
	kinds map[component.TEEKind]host.Provisioner
}

// NewProvisioner returns a composite provisioner that dispatches to the actual provisioner based
// on the component kind.
func NewProvisioner(kinds map[component.TEEKind]host.Provisioner) host.Provisioner {
	return &compositeProvisioner{kinds: kinds}
}

// Implements host.Provisioner.
func (p *compositeProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	var version version.Version
	comps := make(map[component.ID]host.Runtime)

	// Iterate over all wanted components and provision the individual runtimes.
	handlers := make(map[component.ID]host.RuntimeHandler)
	for _, comp := range cfg.Components {
		compCfg := cfg
		compCfg.Components = []*bundle.ExplodedComponent{comp}
		switch comp.Kind {
		case component.RONL:
			version = comp.Version
		case component.ROFL:
			// Wrap message handler for ROFL component.
			handler, err := compCfg.MessageHandler.NewSubHandler(comp.ID())
			if err != nil {
				return nil, fmt.Errorf("host/composite: failed to create sub-handler: %w", err)
			}
			handlers[comp.ID()] = handler
			compCfg.MessageHandler = handler
		default:
		}

		provisioner, ok := p.kinds[comp.TEEKind]
		if !ok {
			return nil, fmt.Errorf("host/composite: provisioner for kind '%s' is not available", comp.TEEKind)
		}
		compRt, err := provisioner.NewRuntime(compCfg)
		if err != nil {
			return nil, fmt.Errorf("host/composite: failed to provision runtime component '%s': %w", comp.ID(), err)
		}

		comps[comp.ID()] = compRt
	}

	ronl, ok := comps[component.ID_RONL]
	if !ok {
		return nil, fmt.Errorf("host/composite: required RONL component not available")
	}

	for id, handler := range handlers {
		if err := handler.AttachRuntime(id, comps[id]); err != nil {
			return nil, fmt.Errorf("failed to attach ROFL host: %w", err)
		}
		if err := handler.AttachRuntime(component.ID_RONL, ronl); err != nil {
			return nil, fmt.Errorf("failed to attach RONL host: %w", err)
		}
	}

	switch {
	case len(comps) == 0:
		// No components are available to be provisioned.
		return nil, fmt.Errorf("host/composite: no components available for provisioning")
	case len(comps) == 1:
		// If there is only a single component, just return the component itself as it doesn't make
		// any sense to have another layer of indirection. This is always the RONL component.
		return comps[component.ID_RONL], nil
	default:
		// Multiple components, create a composite runtime.
		return NewHost(cfg.ID, version, comps), nil
	}
}

// Implements host.Provisioner.
func (p *compositeProvisioner) Name() string {
	if len(p.kinds) == 0 {
		return "composite{}"
	}

	atoms := make([]string, 0, len(p.kinds))
	for kind, provisioner := range p.kinds {
		atoms = append(atoms, kind.String()+": "+provisioner.Name())
	}
	// Ensure deterministic order.
	slices.Sort(atoms)

	return "composite{" + strings.Join(atoms, ", ") + "}"
}
