// Package config implements global configuration options.
package config

import (
	"fmt"
	"net"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

// oasisBundleRegistryURL is the URL of the metadata folder in the Oasis bundle registry.
const oasisBundleRegistryURL = "https://raw.githubusercontent.com/oasisprotocol/bundle-registry/main/metadata/"

// RuntimeProvisioner is the runtime provisioner.
type RuntimeProvisioner string

const (
	// RuntimeProvisionerMock is the name of the mock runtime provisioner.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerMock RuntimeProvisioner = "mock"

	// RuntimeProvisionerUnconfined is the name of the unconfined runtime
	// provisioner that executes runtimes as regular processes without any
	// sandboxing.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerUnconfined RuntimeProvisioner = "unconfined"

	// RuntimeProvisionerSandboxed is the name of the sandboxed runtime
	// provisioner that executes runtimes as regular processes in a Linux
	// namespaces/cgroups/SECCOMP sandbox.
	RuntimeProvisionerSandboxed RuntimeProvisioner = "sandboxed"
)

// UnmarshalText decodes a text marshaled runtime provisioner.
func (m *RuntimeProvisioner) UnmarshalText(text []byte) error {
	switch string(text) {
	case string(RuntimeProvisionerMock):
		*m = RuntimeProvisionerMock
	case string(RuntimeProvisionerUnconfined):
		*m = RuntimeProvisionerUnconfined
	case string(RuntimeProvisionerSandboxed):
		*m = RuntimeProvisionerSandboxed
	default:
		return fmt.Errorf("invalid runtime provisioner: %s", string(text))
	}
	return nil
}

// RuntimeEnvironment is the runtime environment.
type RuntimeEnvironment string

const (
	// RuntimeEnvironmentSGX specifies to run the runtime in SGX.
	RuntimeEnvironmentSGX RuntimeEnvironment = "sgx"

	// RuntimeEnvironmentSGXMock specifies to run the runtime in mocked SGX.
	//
	// Use of this runtime environment is only allowed if DebugDontBlameOasis flag is set.
	RuntimeEnvironmentSGXMock RuntimeEnvironment = "sgx-mock"

	// RuntimeEnvironmentAuto specifies to run the runtime in the most appropriate location.
	RuntimeEnvironmentAuto RuntimeEnvironment = "auto"
)

// TEESelectMode is the selection mode for the Trusted Execution Environment (TEE).
type TEESelectMode string

const (
	// TEESelectModeAuto specifies that the runtime should run in the most appropriate TEE.
	TEESelectModeAuto TEESelectMode = ""

	// TEESelectModeNone specifies that the runtime should run without using any TEE.
	TEESelectModeNone TEESelectMode = "none"

	// TEESelectModeSGX specifies that the runtime should run in an SGX environment.
	TEESelectModeSGX TEESelectMode = "sgx"

	// TEESelectModeTDX specifies that the runtime should run in a TDX environment.
	TEESelectModeTDX TEESelectMode = "tdx"
)

// Config is the runtime registry configuration structure.
type Config struct {
	// Runtimes is the list of runtimes to configure.
	Runtimes []RuntimeConfig `yaml:"runtimes,omitempty"`

	// Paths to runtime bundles.
	Paths []string `yaml:"paths,omitempty"`

	// Runtime provisioner to use (mock, unconfined, sandboxed).
	Provisioner RuntimeProvisioner `yaml:"provisioner"`

	// Path to the sandbox binary (bubblewrap).
	SandboxBinary string `yaml:"sandbox_binary,omitempty"`

	// Path to SGX runtime loader binary (for SGX runtimes).
	// NOTE: This may go away in the future, use `SGX.Loader` instead.
	SGXLoader string `yaml:"sgx_loader,omitempty"`

	// The runtime environment (sgx, elf, auto).
	// NOTE: This may go away in the future, use `DebugMockTEE` instead.
	Environment RuntimeEnvironment `yaml:"environment,omitempty"`

	// History pruner configuration.
	Prune PruneConfig `yaml:"prune,omitempty"`

	// Indexer is history indexer configuration.
	Indexer IndexerConfig `yaml:"indexer,omitempty"`

	// RuntimeConfig maps runtime IDs to their respective local configurations.
	// NOTE: This may go away in the future, use `RuntimeConfig.Config` instead.
	RuntimeConfig map[string]map[string]any `yaml:"config,omitempty"`

	// Address(es) of sentry node(s) to connect to of the form [PubKey@]ip:port
	// (where the PubKey@ part represents base64 encoded node TLS public key).
	SentryAddresses []string `yaml:"sentry_addresses,omitempty"`

	// Transaction pool configuration.
	TxPool tpConfig.Config `yaml:"tx_pool,omitempty"`

	// Number of epochs before runtime activation epoch when to start the runtime to warm it up and
	// prepare any required attestations. Zero disables pre-warming.
	PreWarmEpochs uint64 `yaml:"pre_warm_epochs,omitempty"`

	// AttestInterval is the interval for periodic runtime re-attestation. If not specified
	// a default will be used.
	AttestInterval time.Duration `yaml:"attest_interval,omitempty"`

	// LoadBalancer is the load balancer configuration.
	LoadBalancer LoadBalancerConfig `yaml:"load_balancer,omitempty"`

	// Registries is the list of base URLs used to fetch runtime bundle metadata.
	//
	// The actual metadata URLs are constructed by appending the manifest hash
	// to the base URL. Therefore, the provided URLs don't need to be valid
	// endpoints themselves, only the constructed URLs need to be valid.
	Registries []string `yaml:"registries,omitempty"`

	// MaxBundleSize is the maximum allowed bundle size.
	//
	// If not specified, a default value is used.
	MaxBundleSize string `yaml:"max_bundle_size,omitempty"`

	// DebugMockTEE enables mocking of the Trusted Execution Environment (TEE).
	//
	// This flag can only be used if the DebugDontBlameOasis flag is set.
	DebugMockTEE bool `yaml:"debug_mock_tee,omitempty"`

	// SGX is configuration specific to Intel SGX.
	SGX SgxConfig `yaml:"sgx,omitempty"`

	// TDX is configuration specific to Intel TDX.
	TDX TdxConfig `yaml:"tdx,omitempty"`

	// Log is the runtime log config.
	Log LogConfig `yaml:"log,omitempty"`
}

// GetComponent returns the configuration for the given component
// of the specified runtime, if it exists.
func (c *Config) GetComponent(runtimeID common.Namespace, compID component.ID) (ComponentConfig, bool) {
	for _, rt := range c.Runtimes {
		if rt.ID != runtimeID {
			continue
		}
		for _, comp := range rt.Components {
			if comp.ID == compID {
				return comp, true
			}
		}
	}

	return ComponentConfig{}, false
}

// GetLocalConfig returns the local configuration for the given runtime,
// if it exists.
func (c *Config) GetLocalConfig(runtimeID common.Namespace) map[string]any {
	for _, rt := range c.Runtimes {
		if rt.ID == runtimeID {
			return rt.Config
		}
	}

	// Support legacy configuration where the runtime configuration is defined
	// at the top level.
	return c.RuntimeConfig[runtimeID.String()]
}

// SgxConfig is configuration specific to Intel SGX.
type SgxConfig struct {
	// Loader is the path to the SGX runtime loader binary.
	Loader string `yaml:"loader,omitempty"`
}

// TdxConfig is configuration specific to Intel TDX.
type TdxConfig struct {
	// CidStart is the start of the CID range allocated to VMs.
	CidStart uint32 `yaml:"cid_start,omitempty"`
	// CidCount is the number of CIDs allocated to VMs.
	CidCount uint32 `yaml:"cid_count,omitempty"`
}

// LogConfig is the runtime log configuration.
type LogConfig struct {
	// MaxLogSize is the maximum log size in bytes.
	MaxLogSize int `yaml:"max_log_size,omitempty"`
}

// Validate validates the log configuration for correctness.
func (l *LogConfig) Validate() error {
	if l.MaxLogSize < 1024 {
		return fmt.Errorf("maximum log size must be at least 1024 bytes")
	}
	return nil
}

// RuntimeConfig is the runtime configuration.
type RuntimeConfig struct {
	// ID is the runtime identifier.
	ID common.Namespace `yaml:"id"`

	// Components is the list of components to configure.
	Components []ComponentConfig `yaml:"components,omitempty"`

	// Config contains runtime local configuration.
	// NOTE: This may go away in the future, use `Components.Config` instead.
	Config map[string]any `yaml:"config,omitempty"`

	// Registries is the list of base URLs used to fetch runtime bundle metadata.
	//
	// The actual metadata URLs are constructed by appending the manifest hash
	// to the base URL. Therefore, the provided URLs don't need to be valid
	// endpoints themselves, only the constructed URLs need to be valid.
	Registries []string `yaml:"registries,omitempty"`
}

// Validate validates the runtime configuration.
func (c *RuntimeConfig) Validate() error {
	for _, comp := range c.Components {
		if err := comp.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ComponentConfig is the component configuration.
type ComponentConfig struct {
	// ID is the component identifier.
	ID component.ID `yaml:"id"`

	// TEE specifies the kind of Trusted Execution Environment (TEE)
	// in which the component should run (none, sgx, tdx).
	//
	// If not provided, the TEE kind is selected automatically.
	TEE TEESelectMode `yaml:"tee,omitempty"`

	// Disabled specifies whether the component is disabled. If a component is specified and not
	// disabled, it is enabled.
	Disabled bool `yaml:"disabled,omitempty"`

	// Networking contains the networking configuration for a component.
	Networking NetworkingConfig `yaml:"networking,omitempty"`

	// Permissions is the list of permissions for this component.
	Permissions []ComponentPermission `yaml:"permissions,omitempty"`

	// Config contains component local configuration.
	Config map[string]any `yaml:"config,omitempty"`
}

// Validate validates the component configuration.
func (c *ComponentConfig) Validate() error {
	switch c.TEE {
	case TEESelectModeAuto:
	case TEESelectModeNone:
	case TEESelectModeSGX:
	case TEESelectModeTDX:
	default:
		return fmt.Errorf("unknown TEE select mode: %s", c.TEE)
	}

	return nil
}

// TEEKind returns the kind of Trusted Execution Environment (TEE)
// in which the component should run, if it is specified.
func (c *ComponentConfig) TEEKind() (component.TEEKind, bool) {
	switch c.TEE {
	case TEESelectModeNone:
		return component.TEEKindNone, true
	case TEESelectModeSGX:
		return component.TEEKindSGX, true
	case TEESelectModeTDX:
		return component.TEEKindTDX, true
	default:
		return 0, false
	}
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *ComponentConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.ShortTag() {
	case "!!str":
		// String, treat as just component identifier that enables the component.
		*c = ComponentConfig{
			Disabled: false,
		}
		return value.Decode(&c.ID)
	default:
		type compConfig ComponentConfig
		return value.Decode((*compConfig)(c))
	}
}

// HasPermission returns true iff the component has a given permission configured.
func (c *ComponentConfig) HasPermission(perm ComponentPermission) bool {
	return slices.Contains(c.Permissions, perm)
}

// ComponentPermission represents a permission given to a component.
type ComponentPermission string

const (
	// PermissionBundleAdd is the permission that grants the component rights to provision other
	// bundles.
	PermissionBundleAdd ComponentPermission = "bundle_add"

	// PermissionBundleRemove is the permission that grants the component rights to remove other
	// bundles that were previously added by it (e.g. it cannot remove unrelated bundles).
	PermissionBundleRemove ComponentPermission = "bundle_remove"

	// PermissionVolumeAdd is the permission that grants the component rights to add volumes.
	PermissionVolumeAdd ComponentPermission = "volume_add"

	// PermissionVolumeRemove is the permission that grants the component rights to remove volumes.
	PermissionVolumeRemove ComponentPermission = "volume_remove"

	// PermissionLogView is the permission that grants the component rights to view logs.
	PermissionLogView ComponentPermission = "log_view"
)

// NetworkingConfig is the networking configuration.
type NetworkingConfig struct {
	// Incoming is a list of IPs/ports to expose to the component from the host.
	Incoming []IncomingNetworkingConfig `yaml:"incoming,omitempty"`
}

// IncomingNetworkingConfig describes an IP/port to expose to the component from the host.
type IncomingNetworkingConfig struct {
	// IP is the host IP address to expose to the component.
	IP string `yaml:"ip,omitempty"`
	// Protocol is the optional protocol to expose to the component.
	Protocol string `yaml:"protocol,omitempty"`
	// SrcPort is the source port (on the host).
	SrcPort uint16 `yaml:"src_port"`
	// DstPort is the optional destination port (in the component).
	DstPort uint16 `yaml:"dst_port,omitempty"`
}

// PruneConfig is the history pruner configuration structure.
type PruneConfig struct {
	// History pruner strategy.
	Strategy string `yaml:"strategy"`
	// History pruning interval.
	Interval time.Duration `yaml:"interval"`
	// Number of last rounds to keep.
	NumKept uint64 `yaml:"num_kept"`
}

// IsEnabled returns true when pruning is enabled.
func (p PruneConfig) IsEnabled() bool {
	return p.Strategy != "none"
}

// IndexerConfig is history indexer configuration.
type IndexerConfig struct {
	// BatchSize is max number of blocks committed in a batch during history reindex.
	//
	// Setting it to zero uses the default batch size.
	BatchSize uint16 `yaml:"batch_size,omitempty"`
}

// LoadBalancerConfig is the load balancer configuration.
type LoadBalancerConfig struct {
	// NumInstances is the number of runtime instances to provision for load-balancing.
	//
	// Setting it to zero or one disables load balancing.
	NumInstances uint64 `yaml:"num_instances,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	switch c.Provisioner {
	case RuntimeProvisionerMock:
	case RuntimeProvisionerUnconfined:
	case RuntimeProvisionerSandboxed:
		if c.SandboxBinary == "" {
			return fmt.Errorf("sandbox_binary must be set when using sandboxed provisioner")
		}
	default:
		return fmt.Errorf("unknown runtime provisioner: %s", c.Provisioner)
	}

	switch c.Environment {
	case RuntimeEnvironmentSGX:
		if c.SGXLoader == "" && c.SGX.Loader == "" {
			return fmt.Errorf("sgx.loader must be set when using sgx environment")
		}
		if c.SGXLoader != "" && c.SGX.Loader != "" {
			return fmt.Errorf("only one of sgx_loader and sgx.loader must be set")
		}
	case RuntimeEnvironmentSGXMock:
	case RuntimeEnvironmentAuto:
	default:
		return fmt.Errorf("unknown runtime environment: %s", c.Environment)
	}

	switch c.Prune.Strategy {
	case "none":
	case "keep_last":
		if c.Prune.Interval < 1*time.Second {
			return fmt.Errorf("prune.interval must be >= 1 second")
		}
	default:
		return fmt.Errorf("unknown runtime history pruner strategy: %s", c.Prune.Strategy)
	}

	if c.LoadBalancer.NumInstances > 128 {
		return fmt.Errorf("cannot specify more than 128 instances for load balancing")
	}

	if err := c.Log.Validate(); err != nil {
		return err
	}

	for _, rt := range c.Runtimes {
		if err := rt.Validate(); err != nil {
			return err
		}
	}
	return c.validateNetworking()
}

func (c *Config) validateNetworking() error {
	// Validate combined network configurations to quickly check there is no overlap.
	type usedPort struct {
		proto string
		port  uint16
	}
	const anyIP = "0.0.0.0"
	usedPorts := make(map[usedPort]map[string]struct{})
	for _, rt := range c.Runtimes {
		for _, comp := range rt.Components {
			for _, compNet := range comp.Networking.Incoming {
				var proto string
				switch compNet.Protocol {
				case "tcp", "udp":
					proto = compNet.Protocol
				case "":
					proto = "tcp"
				default:
					return fmt.Errorf("component %s: network protocol '%s' not supported", comp.ID, compNet.Protocol)
				}

				ip := compNet.IP
				if ip == "" {
					ip = anyIP
				}
				parsedIP := net.ParseIP(ip)
				if parsedIP == nil {
					return fmt.Errorf("component %s: IP address '%s' is malformed", comp.ID, ip)
				}
				// Ensure canonical representation.
				if parsedIP.IsUnspecified() {
					ip = anyIP
				} else {
					ip = parsedIP.String()
				}

				up := usedPort{proto, compNet.SrcPort}

				switch ip {
				case anyIP:
					if _, ok := usedPorts[up]; ok {
						return fmt.Errorf("component %s: overlapping incoming IP/protocol/port", comp.ID)
					}
				default:
					if _, ok := usedPorts[up][ip]; ok {
						return fmt.Errorf("component %s: overlapping incoming IP/protocol/port", comp.ID)
					}
					if _, ok := usedPorts[up][anyIP]; ok {
						return fmt.Errorf("component %s: overlapping incoming IP/protocol/port", comp.ID)
					}
				}

				if _, ok := usedPorts[up]; !ok {
					usedPorts[up] = make(map[string]struct{})
				}
				usedPorts[up][ip] = struct{}{}
			}
		}
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Runtimes:      make([]RuntimeConfig, 0),
		Paths:         []string{},
		Provisioner:   RuntimeProvisionerSandboxed,
		SandboxBinary: "/usr/bin/bwrap",
		SGXLoader:     "",
		Environment:   RuntimeEnvironmentAuto,
		Prune: PruneConfig{
			Strategy: "none",
			Interval: 2 * time.Minute,
			NumKept:  250_000,
		},
		Indexer: IndexerConfig{
			BatchSize: 1000,
		},
		SentryAddresses: []string{},
		TxPool: tpConfig.Config{
			MaxPoolSize:          50_000,
			MaxLastSeenCacheSize: 100_000,
			MaxCheckTxBatchSize:  128,
			RecheckInterval:      5,
			RepublishInterval:    60 * time.Second,
		},
		PreWarmEpochs: 3,
		LoadBalancer: LoadBalancerConfig{
			NumInstances: 0,
		},
		Registries: []string{oasisBundleRegistryURL},
		SGX: SgxConfig{
			Loader: "",
		},
		TDX: TdxConfig{
			CidStart: 0xA5150000,
			CidCount: 1024,
		},
		Log: LogConfig{
			MaxLogSize: 1024 * 1024,
		},
	}
}
