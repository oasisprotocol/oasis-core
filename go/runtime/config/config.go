// Package config implements global configuration options.
package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

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

	// RuntimeEnvironmentELF specifies to run the runtime in the OS address space.
	//
	// Use of this runtime environment is only allowed if DebugDontBlameOasis flag is set.
	RuntimeEnvironmentELF RuntimeEnvironment = "elf"

	// RuntimeEnvironmentAuto specifies to run the runtime in the most appropriate location.
	RuntimeEnvironmentAuto RuntimeEnvironment = "auto"
)

// Config is the runtime registry configuration structure.
type Config struct {
	// Runtime provisioner to use (mock, unconfined, sandboxed).
	Provisioner RuntimeProvisioner `yaml:"provisioner"`
	// Paths to runtime bundles.
	Paths []string `yaml:"paths"`
	// Path to the sandbox binary (bubblewrap).
	SandboxBinary string `yaml:"sandbox_binary"`
	// Path to SGXS runtime loader binary (for SGX runtimes).
	SGXLoader string `yaml:"sgx_loader"`
	// The runtime environment (sgx, elf, auto).
	Environment RuntimeEnvironment `yaml:"environment"`

	// History pruner configuration.
	Prune PruneConfig `yaml:"prune,omitempty"`

	// Runtime ID -> local config.
	RuntimeConfig map[string]interface{} `yaml:"config,omitempty"`

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

	// Components is the list of components to configure.
	Components []ComponentConfig `yaml:"components,omitempty"`
}

// GetComponent returns configuration for the given component if it exists.
func (c *Config) GetComponent(id component.ID) (ComponentConfig, bool) {
	for _, comp := range c.Components {
		if comp.ID == id {
			return comp, true
		}
	}
	return ComponentConfig{}, false
}

// ComponentConfig is the component configuration.
type ComponentConfig struct {
	// ID is the component identifier.
	ID component.ID `yaml:"id"`

	// Disabled specifies whether the component is disabled. If a component is specified and not
	// disabled, it is enabled.
	Disabled bool `yaml:"disabled,omitempty"`
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

// PruneConfig is the history pruner configuration structure.
type PruneConfig struct {
	// History pruner strategy.
	Strategy string `yaml:"strategy"`
	// History pruning interval.
	Interval time.Duration `yaml:"interval"`
	// Number of last rounds to keep.
	NumKept uint64 `yaml:"num_kept"`
}

// LoadBalancerConfig is the load balancer configuration.
type LoadBalancerConfig struct {
	// NumInstances is the number of runtime instances to provision for load-balancing. Setting it
	// to zero (default) or one disables load balancing.
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
		if c.SGXLoader == "" {
			return fmt.Errorf("sgx_loader must be set when using sgx environment")
		}
	case RuntimeEnvironmentELF:
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
		return fmt.Errorf("unknown runtime history pruner strategy: %s", c.Environment)
	}

	if c.LoadBalancer.NumInstances > 128 {
		return fmt.Errorf("cannot specify more than 128 instances for load balancing")
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Provisioner:   RuntimeProvisionerSandboxed,
		Paths:         []string{},
		SandboxBinary: "/usr/bin/bwrap",
		SGXLoader:     "",
		Environment:   RuntimeEnvironmentAuto,
		Prune: PruneConfig{
			Strategy: "none",
			Interval: 2 * time.Minute,
			NumKept:  600,
		},
		RuntimeConfig:   nil,
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
	}
}
