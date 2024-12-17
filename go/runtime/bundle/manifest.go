package bundle

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

const (
	manifestPath = "META-INF"
	manifestName = manifestPath + "/MANIFEST.MF"
)

// Manifest is a deserialized runtime bundle manifest.
type Manifest struct {
	// Name is the optional human readable runtime name.
	Name string `json:"name,omitempty"`

	// ID is the runtime identifier.
	ID common.Namespace `json:"id"`

	// Version is the runtime version.
	// NOTE: This may go away in the future, use `Component.Version` instead.
	Version version.Version `json:"version,omitempty"`

	// Executable is the name of the runtime ELF executable file.
	// NOTE: This may go away in the future, use `Components` instead.
	Executable string `json:"executable,omitempty"`

	// SGX is the SGX specific manifest metadata if any.
	// NOTE: This may go away in the future, use `Components` instead.
	SGX *SGXMetadata `json:"sgx,omitempty"`

	// Components are the additional runtime components.
	Components []*Component `json:"components,omitempty"`

	// Digests is the cryptographic digests of the bundle contents,
	// excluding the manifest.
	Digests map[string]hash.Hash `json:"digests"`
}

// Hash returns a cryptographic hash of the CBOR-serialized manifest.
func (m *Manifest) Hash() hash.Hash {
	return hash.NewFrom(m)
}

// IsLegacy returns true iff this is a legacy manifest that defines executables at the top level.
func (m *Manifest) IsLegacy() bool {
	return len(m.Executable) > 0 || m.SGX != nil
}

// Validate validates the manifest structure for well-formedness.
func (m *Manifest) Validate() error {
	byID := make(map[component.ID]struct{})
	for i, c := range m.Components {
		// Ensure there are no duplicate components.
		if _, ok := byID[c.ID()]; ok {
			return fmt.Errorf("component %d: another component with id '%s' already exists", i, c.ID())
		}
		byID[c.ID()] = struct{}{}

		// Validate each component.
		if err := c.Validate(); err != nil {
			return fmt.Errorf("component %d: %w", i, err)
		}
	}

	if _, ok := byID[component.ID_RONL]; ok && m.IsLegacy() {
		return fmt.Errorf("manifest defines both legacy and componentized RONL component")
	}

	// Validate legacy manifest.
	if m.SGX != nil {
		err := m.SGX.Validate()
		if err != nil {
			return fmt.Errorf("sgx: %w", err)
		}
	}

	return nil
}

// IsDetached returns true iff the manifest does not include a RONL component. Such bundles require
// that the RONL component is provided out-of-band (e.g. in a separate bundle).
func (m *Manifest) IsDetached() bool {
	return m.GetComponentByID(component.ID_RONL) == nil
}

// GetAvailableComponents collects all of the available components into a map.
func (m *Manifest) GetAvailableComponents() map[component.ID]*Component {
	availableComps := make(map[component.ID]*Component)
	for _, comp := range m.Components {
		availableComps[comp.ID()] = comp
	}
	if _, exists := availableComps[component.ID_RONL]; !exists && !m.IsDetached() {
		// Needed for supporting legacy manifests.
		availableComps[component.ID_RONL] = m.GetComponentByID(component.ID_RONL)
	}
	return availableComps
}

// GetComponentByID returns the first component with the given kind.
func (m *Manifest) GetComponentByID(id component.ID) *Component {
	for _, c := range m.Components {
		if c.Matches(id) {
			return c
		}
	}

	// We also support legacy manifests which define the RONL component at the top-level.
	if id.IsRONL() && m.IsLegacy() {
		return &Component{
			Kind:    component.RONL,
			Version: m.Version,
			ELF: &ELFMetadata{
				Executable: m.Executable,
			},
			SGX: m.SGX,
		}
	}
	return nil
}

// GetVersion returns the runtime version.
func (m *Manifest) GetVersion() version.Version {
	// We also support legacy manifests which define version at the top-level.
	for _, comp := range m.Components {
		if !comp.ID().IsRONL() {
			continue
		}

		if comp.Version.ToU64() > m.Version.ToU64() {
			return comp.Version
		}

		break
	}

	return m.Version
}
