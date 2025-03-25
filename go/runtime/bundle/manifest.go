package bundle

import (
	"encoding/json"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/volume"
)

const (
	manifestPath = "META-INF"
	manifestName = manifestPath + "/MANIFEST.MF"
)

// ExplodedManifest is manifest with corresponding exploded bundle dir.
type ExplodedManifest struct {
	*Manifest

	// ExplodedDataDir is the path to the data directory where the bundle
	// represented by manifest has been extracted.
	ExplodedDataDir string

	// Labels are labels attached to the manifest by the registry.
	Labels map[string]string

	// Volumes are the volumes attached to this exploded manifest.
	Volumes map[string]*volume.Volume
}

// HasLabels returns true iff the exploded manifest has all of the given labels set.
func (m *ExplodedManifest) HasLabels(labels map[string]string) bool {
	for key, value := range labels {
		if v, ok := m.Labels[key]; !ok || v != value {
			return false
		}
	}
	return true
}

// ValidateVolumes validates that the exploded manifest has all of the required volumes present.
func (m *ExplodedManifest) ValidateVolumes() error {
	for _, comp := range m.Components {
		for _, volName := range comp.RequiredVolumeNames() {
			if _, ok := m.Volumes[volName]; !ok {
				return fmt.Errorf("missing required volume '%s'", volName)
			}
		}
	}
	return nil
}

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
	// Support legacy manifests where the runtime version is defined at the top level.
	if m.Version.ToU64() > 0 {
		for _, comp := range m.Components {
			if comp.ID().IsRONL() {
				v := comp.Version
				comp.Version = version.Version{}
				h := hash.NewFrom(m)
				comp.Version = v
				return h
			}
		}
	}

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
	_, ok := m.GetComponentByID(component.ID_RONL)
	return !ok
}

// GetAvailableComponents collects all of the available components into a map.
func (m *Manifest) GetAvailableComponents() map[component.ID]*Component {
	availableComps := make(map[component.ID]*Component)
	for _, comp := range m.Components {
		availableComps[comp.ID()] = comp
	}
	if _, exists := availableComps[component.ID_RONL]; !exists && !m.IsDetached() {
		// Needed for supporting legacy manifests.
		availableComps[component.ID_RONL], _ = m.GetComponentByID(component.ID_RONL)
	}
	return availableComps
}

// GetComponentByID returns the first component with the given kind.
func (m *Manifest) GetComponentByID(id component.ID) (*Component, bool) {
	for _, c := range m.Components {
		if c.Matches(id) {
			return c, true
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
		}, true
	}
	return nil, false
}

// UnmarshalJSON customizes the unmarshalling of the manifest.
func (m *Manifest) UnmarshalJSON(b []byte) (err error) {
	// Unmarshal into the auxiliary struct to avoid recursion.
	type alias Manifest
	aux := (*alias)(m)
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}

	// Support legacy manifests where the runtime version is defined at the top level.
	if m.Version.ToU64() > 0 {
		for _, comp := range m.Components {
			if comp.ID().IsRONL() {
				comp.Version = m.Version
				break
			}
		}
	}

	return nil
}
