package composite

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
)

type compositeProvisioner struct {
	kinds map[component.TEEKind]host.Provisioner
}

// NewProvisioner returns a new composite provisioner that dispatches
// to the actual provisioner based on the component kind.
func NewProvisioner(kinds map[component.TEEKind]host.Provisioner) host.Provisioner {
	return &compositeProvisioner{kinds: kinds}
}

// Implements host.Provisioner.
func (p *compositeProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	provisioner, ok := p.kinds[cfg.Component.TEEKind]
	if !ok {
		return nil, fmt.Errorf("host/composite/provisioner: kind '%s' is not available", cfg.Component.TEEKind)
	}
	return provisioner.NewRuntime(cfg)
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
