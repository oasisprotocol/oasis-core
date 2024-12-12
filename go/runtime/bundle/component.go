package bundle

import (
	"fmt"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// ExplodedComponent is an exploded runtime component ready for execution.
type ExplodedComponent struct {
	*Component

	// Detached is true iff the bundle containing the component does not
	// include a RONL component.
	Detached bool

	// ExplodedDataDir is the path to the data directory where the bundle
	// containing the component has been extracted.
	ExplodedDataDir string
}

// ExplodedPath returns the path that the corresponding asset will be written to via WriteExploded.
func (c *ExplodedComponent) ExplodedPath(fn string) string {
	return filepath.Join(c.ExplodedDataDir, fn)
}

// Component is a runtime component.
type Component struct {
	// Kind is the component kind.
	Kind component.Kind `json:"kind"`

	// Name is the name of the component that can be used to filter components when multiple are
	// provided by a runtime.
	Name string `json:"name,omitempty"`

	// Version is the component version.
	Version version.Version

	// Executable is the name of the runtime ELF executable file if any.
	Executable string `json:"executable,omitempty"`

	// SGX is the SGX specific manifest metadata if any.
	SGX *SGXMetadata `json:"sgx,omitempty"`

	// TDX is the TDX specific manifest metadata if any.
	TDX *TDXMetadata `json:"tdx,omitempty"`

	// Identities are the (optional) expected enclave identities. When not provided, it must be
	// computed at runtime. In the future, this field will become required.
	//
	// Multiple identities may be provided because they can differ across different deployment
	// systems (e.g. hypervisors).
	Identities []Identity `json:"identity,omitempty"`

	// Disabled specifies whether the component is disabled by default and needs to be explicitly
	// enabled via node configuration to be used.
	Disabled bool `json:"disabled,omitempty"`
}

// ID returns this component's identifier.
func (c *Component) ID() component.ID {
	return component.ID{Kind: c.Kind, Name: c.Name}
}

// Matches returns true iff the component matches the given component ID.
func (c *Component) Matches(id component.ID) bool {
	return c.ID() == id
}

// Validate validates the component structure for well-formedness.
func (c *Component) Validate() error {
	if !common.AtMostOneTrue(
		c.SGX != nil,
		c.TDX != nil,
	) {
		return fmt.Errorf("each component can only include metadata for a single TEE")
	}
	if c.SGX != nil {
		err := c.SGX.Validate()
		if err != nil {
			return fmt.Errorf("sgx: %w", err)
		}
	}
	if c.TDX != nil {
		err := c.TDX.Validate()
		if err != nil {
			return fmt.Errorf("tdx: %w", err)
		}
	}

	switch c.Kind {
	case component.RONL:
		if c.Name != "" {
			return fmt.Errorf("RONL component must have an empty name")
		}
		if c.Executable == "" {
			return fmt.Errorf("RONL component must define an executable")
		}
		if c.Disabled {
			return fmt.Errorf("RONL component cannot be disabled")
		}
	case component.ROFL:
	default:
		return fmt.Errorf("unknown component kind: '%s'", c.Kind)
	}
	return nil
}

// IsNetworkAllowed returns true if network access should be allowed for the component.
func (c *Component) IsNetworkAllowed() bool {
	switch c.Kind {
	case component.ROFL:
		// Off-chain logic is allowed to access the network.
		return true
	default:
		// Network access is generally not allowed.
		return false
	}
}

// IsTEERequired returns true iff the component only provides TEE executables.
func (c *Component) IsTEERequired() bool {
	return c.Executable == "" && c.TEEKind() != component.TEEKindNone
}

// TEEKind returns the kind of TEE supported by the component.
func (c *Component) TEEKind() component.TEEKind {
	switch {
	case c.TDX != nil:
		return component.TEEKindTDX
	case c.SGX != nil:
		return component.TEEKindSGX
	default:
		return component.TEEKindNone
	}
}
