package bundle

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
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
			Kind:       component.RONL,
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

// TDXMetadata is the TDX specific manifest metadata.
//
// Note that changes to these fields may change the TD measurements.
type TDXMetadata struct {
	// Firmware is the name of the virtual firmware file. It should rarely change and multiple
	// components may use the same firmware.
	Firmware string `json:"firmware"`
	// Kernel is the name of the kernel image file. It should rarely change and multiple components
	// may use the same kernel.
	Kernel string `json:"kernel,omitempty"`
	// InitRD is the name of the initial RAM disk image file. It should rarely change and multiple
	// components may use the same initrd.
	InitRD string `json:"initrd,omitempty"`
	// ExtraKernelOptions are the extra kernel options to pass to the kernel after any of the
	// default options. Note that kernel options affect TD measurements.
	ExtraKernelOptions []string `json:"extra_kernel_options,omitempty"`

	// Stage2Image is the name of the stage 2 VM image file.
	Stage2Image string `json:"stage2_image,omitempty"`

	// Resources are the requested VM resources.
	Resources TDXResources `json:"resources"`
}

// Validate validates the TDX metadata structure for well-formedness.
func (t *TDXMetadata) Validate() error {
	if t.Firmware == "" {
		return fmt.Errorf("firmware must be set")
	}
	if !t.HasKernel() && t.HasStage2() {
		return fmt.Errorf("kernel must be set if stage 2 image is set")
	}
	if !t.HasKernel() && t.HasInitRD() {
		return fmt.Errorf("kernel must be set if initrd image is set")
	}
	if err := t.Resources.Validate(); err != nil {
		return err
	}
	return nil
}

// HasKernel returns true iff the TDX metadata indicates there is a kernel present.
func (t *TDXMetadata) HasKernel() bool {
	return t.Kernel != ""
}

// HasInitRD returns true iff the TDX metadata indicates there is an initial RAM disk image present.
func (t *TDXMetadata) HasInitRD() bool {
	return t.InitRD != ""
}

// HasStage2 returns true iff the TDX metadata indicates there is a stage 2 image present.
func (t *TDXMetadata) HasStage2() bool {
	return t.Stage2Image != ""
}

// TDXResources are the requested VM resources for TDX VMs.
//
// Note that changes to these fields may change the TD measurements.
type TDXResources struct {
	// Memory is the requested VM memory amount in megabytes.
	Memory uint64 `json:"memory"`
	// CPUCount is the requested number of vCPUs.
	CPUCount uint8 `json:"cpus"`
}

// Validate validates the VM resources.
func (r *TDXResources) Validate() error {
	if r.Memory < 16 {
		return fmt.Errorf("memory limit must be at least 16M")
	}
	if r.CPUCount < 1 {
		return fmt.Errorf("vCPU count must be at least 1")
	}
	return nil
}

// Identity is the cryptographic identity of a component.
type Identity struct {
	// Hypervisor is the optional hypervisor this identity is for.
	Hypervisor string `json:"hypervisor,omitempty"`

	// Enclave is the enclave identity.
	Enclave sgx.EnclaveIdentity `json:"enclave"`
}

// Component is a runtime component.
type Component struct {
	// Kind is the component kind.
	Kind component.Kind `json:"kind"`

	// Name is the name of the component that can be used to filter components when multiple are
	// provided by a runtime.
	Name string `json:"name,omitempty"`

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
