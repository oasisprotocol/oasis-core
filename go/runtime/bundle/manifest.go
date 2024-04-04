package bundle

import (
	"fmt"
	"strings"

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

// Validate validates the manifest structure for well-formedness.
func (m *Manifest) Validate() error {
	byID := make(map[ComponentID]struct{})
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

	if _, ok := byID[ComponentID_RONL]; ok && len(m.Executable) > 0 {
		return fmt.Errorf("manifest defines both legacy and componentized RONL component")
	}

	// Validate legacy manifest.
	if m.SGX != nil {
		err := m.SGX.Validate()
		if err != nil {
			return fmt.Errorf("sgx: %w", err)
		}
	}

	// Ensure the RONL component is always defined.
	if ronl := m.GetComponentByID(ComponentID_RONL); ronl == nil {
		return fmt.Errorf("runtime must define at least the RONL component")
	}

	return nil
}

// GetAvailableComponents collects all of the available components into a map.
func (m *Manifest) GetAvailableComponents() map[ComponentID]*Component {
	availableComps := make(map[ComponentID]*Component)
	for _, comp := range m.Components {
		availableComps[comp.ID()] = comp
	}
	if _, exists := availableComps[ComponentID_RONL]; !exists {
		// Needed for supporting legacy manifests -- always available, see Validate above.
		availableComps[ComponentID_RONL] = m.GetComponentByID(ComponentID_RONL)
	}
	return availableComps
}

// GetComponentByID returns the first component with the given kind.
func (m *Manifest) GetComponentByID(id ComponentID) *Component {
	for _, c := range m.Components {
		if c.Matches(id) {
			return c
		}
	}

	// We also support legacy manifests which define the RONL component at the top-level.
	if id == ComponentID_RONL && len(m.Executable) > 0 {
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

// Validate validates the SGX metadata structure for well-formedness.
func (s *SGXMetadata) Validate() error {
	if s.Executable == "" {
		return fmt.Errorf("executable must be set")
	}
	return nil
}

// ComponentKind is the kind of a component.
type ComponentKind string

const (
	// ComponentRONL is the on-chain logic component.
	ComponentRONL ComponentKind = "ronl"
	// ComponentROFL is the off-chain logic component.
	ComponentROFL ComponentKind = "rofl"
)

const kindNameSeparator = "."

// ComponentID is a unique component identifier.
type ComponentID struct {
	// Kind is the component kind.
	Kind ComponentKind `json:"kind"`

	// Name is an optional component name.
	Name string `json:"name,omitempty"`
}

// String returns a string representation of the component identifier.
func (c ComponentID) String() string {
	if c.Name == "" {
		return string(c.Kind)
	}
	return string(c.Kind) + " (" + c.Name + ")"
}

// MarshalText serializes the component identifier into text form.
func (c ComponentID) MarshalText() ([]byte, error) {
	if c.Name == "" {
		return []byte(string(c.Kind)), nil
	}
	return []byte(string(c.Kind) + kindNameSeparator + c.Name), nil
}

// UnmarshalText deserializes the component identifier from text form.
func (c *ComponentID) UnmarshalText(text []byte) error {
	atoms := strings.SplitN(string(text), kindNameSeparator, 2)

	if len(atoms) == 2 && atoms[1] == "" {
		return fmt.Errorf("malformed component identifier")
	}

	var kind ComponentKind
	switch atoms[0] {
	case string(ComponentRONL):
		kind = ComponentRONL
	case string(ComponentROFL):
		kind = ComponentROFL
	default:
		return fmt.Errorf("malformed component kind: %s", atoms[0])
	}

	if kind == ComponentRONL && len(atoms) > 1 && len(atoms[1]) > 0 {
		return fmt.Errorf("RONL component must have an empty name, got: %s", atoms[1])
	}

	c.Kind = kind
	if len(atoms) > 1 {
		c.Name = atoms[1]
	} else {
		c.Name = ""
	}
	return nil
}

// ComponentID_RONL is the identifier of the RONL component.
var ComponentID_RONL = ComponentID{Kind: ComponentRONL, Name: ""} //nolint: revive

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

// ID returns this component's identifier.
func (c *Component) ID() ComponentID {
	return ComponentID{Kind: c.Kind, Name: c.Name}
}

// Matches returns true iff the component matches the given component ID.
func (c *Component) Matches(id ComponentID) bool {
	return c.ID() == id
}

// Validate validates the component structure for well-formedness.
func (c *Component) Validate() error {
	if c.Executable == "" {
		return fmt.Errorf("executable must be set")
	}
	if c.SGX != nil {
		err := c.SGX.Validate()
		if err != nil {
			return fmt.Errorf("sgx: %w", err)
		}
	}

	switch c.Kind {
	case ComponentRONL:
		if c.Name != "" {
			return fmt.Errorf("RONL component must have an empty name")
		}
	case ComponentROFL:
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
