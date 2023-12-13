package bundle

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

const (
	manifestPath = "META-INF"
	manifestName = manifestPath + "/MANIFEST.MF"
)

// Manifest is a deserialized runtime bundle manifest.
type Manifest struct {
	// Name is the optional human readable runtime name.
	Name string `json:"name,omitempty"`

	// ID is the runtime ID.
	ID common.Namespace `json:"id"`

	// Version is the runtime version.
	Version version.Version `json:"version,omitempty"`

	// Executable is the name of the runtime ELF executable file.
	Executable string `json:"executable"`

	// SGX is the SGX specific manifest metadata if any.
	SGX *SGXMetadata `json:"sgx,omitempty"`

	// Components are the additional runtime components.
	Components []*Component `json:"components,omitempty"`

	// Digests is the cryptographic digests of the bundle contents,
	// excluding the manifest.
	Digests map[string]hash.Hash `json:"digests"`
}

// Validate validates the manifest structure for well-formedness.
func (m *Manifest) Validate() error {
	for i, c := range m.Components {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("component %d: %w", i, err)
		}
	}

	// Ensure the RONL component is always defined.
	if ronl := m.GetComponentByKind(ComponentRONL); ronl == nil {
		return fmt.Errorf("runtime must defined at least the RONL component")
	}

	return nil
}

// GetAvailableComponents collects all of the available components into a map.
func (m *Manifest) GetAvailableComponents() map[ComponentKind]*Component {
	availableComps := make(map[ComponentKind]*Component)
	for _, comp := range m.Components {
		availableComps[comp.Kind] = comp
	}
	if _, exists := availableComps[ComponentRONL]; !exists {
		// Needed for supporting legacy manifests -- always available, see Validate above.
		availableComps[ComponentRONL] = m.GetComponentByKind(ComponentRONL)
	}
	return availableComps
}

// GetComponentByKind returns the first component with the given kind.
func (m *Manifest) GetComponentByKind(kind ComponentKind) *Component {
	for _, c := range m.Components {
		if c.Kind == kind {
			return c
		}
	}

	// We also support legacy manifests which define the RONL component at the top-level.
	if kind == ComponentRONL {
		return &Component{
			Kind:       ComponentRONL,
			Executable: m.Executable,
			SGX:        m.SGX,
		}
	}
	return nil
}

// SGXMetadata is the SGX specific manifest metadata.
type SGXMetadata struct {
	// Executable is the name of the SGX enclave executable file.
	Executable string `json:"executable"`

	// Signature is the name of the SGX enclave signature file.
	Signature string `json:"signature"`
}

// ComponentKind is the kind of a component.
type ComponentKind string

const (
	// ComponentInvalid is an invalid component.
	ComponentInvalid ComponentKind = ""
	// ComponentRONL is the on-chain logic component.
	ComponentRONL ComponentKind = "ronl"
	// ComponentROFL is the off-chain logic component.
	ComponentROFL ComponentKind = "rofl"
)

// Component is a runtime component.
type Component struct {
	// Kind is the component kind.
	Kind ComponentKind `json:"kind"`

	// Name is the name of the component that can be used to filter components when multiple are
	// provided by a runtime.
	Name string `json:"name,omitempty"`

	// Executable is the name of the runtime ELF executable file.
	Executable string `json:"executable"`

	// SGX is the SGX specific manifest metadata if any.
	SGX *SGXMetadata `json:"sgx,omitempty"`
}

// Validate validates the component structure for well-formedness.
func (c *Component) Validate() error {
	switch c.Kind {
	case ComponentRONL, ComponentROFL:
	default:
		return fmt.Errorf("unknown component kind: '%s'", c.Kind)
	}
	return nil
}

// IsNetworkAllowed returns true if network access should be allowed for the component.
func (c *Component) IsNetworkAllowed() bool {
	switch c.Kind {
	case ComponentROFL:
		// Off-chain logic is allowed to access the network.
		return true
	default:
		// Network access is generally not allowed.
		return false
	}
}
