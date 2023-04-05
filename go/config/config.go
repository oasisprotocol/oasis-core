// Package config implements global configuration options.
package config

import (
	"bytes"
	"fmt"
	"io"

	"github.com/a8m/envsubst"
	"gopkg.in/yaml.v3"

	tm "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/config"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/config"
	ias "github.com/oasisprotocol/oasis-core/go/ias/config"
	common "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/config"
	metrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics/config"
	pprof "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof/config"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/config"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/config"
	workerKM "github.com/oasisprotocol/oasis-core/go/worker/keymanager/config"
	workerRegistration "github.com/oasisprotocol/oasis-core/go/worker/registration/config"
	workerSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry/config"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/config"
)

// NodeMode is the node mode.
type NodeMode string

const (
	// ModeValidator is the name of the validator node mode.
	ModeValidator NodeMode = "validator"
	// ModeCompute is the name of the compute node mode.
	ModeCompute NodeMode = "compute"
	// ModeKeyManager is the name of the key manager node mode.
	ModeKeyManager NodeMode = "keymanager"
	// ModeClient is the name of the client node mode.
	ModeClient NodeMode = "client"
	// ModeStatelessClient is the name of the stateless client node mode.
	ModeStatelessClient NodeMode = "client-stateless"
	// ModeSeed is the name of the seed node mode.
	ModeSeed NodeMode = "seed"
	// ModeArchive is the name of the archive node mode.
	ModeArchive NodeMode = "archive"
)

// IsClientOnly returns true iff the mode is one that has the node running
// as a client for all configured runtimes.
func (m NodeMode) IsClientOnly() bool {
	switch m {
	case ModeClient, ModeStatelessClient:
		return true
	}
	return false
}

// HasLocalStorage returns true iff the mode is one that has local storage.
func (m NodeMode) HasLocalStorage() bool {
	switch m {
	case ModeClient, ModeCompute:
		return true
	}
	return false
}

// GlobalConfig holds the global configuration options.
var GlobalConfig Config

// Config is the top-level configuration structure.
type Config struct {
	// Oasis node mode (validator, non-validator, compute, keymanager, etc.).
	Mode NodeMode `yaml:"mode"`

	Common    common.Config  `yaml:"common"`
	Genesis   genesis.Config `yaml:"genesis"`
	Consensus tm.Config      `yaml:"consensus"`
	Runtime   runtime.Config `yaml:"runtime"`
	P2P       p2p.Config     `yaml:"p2p"`
	IAS       ias.Config     `yaml:"ias,omitempty"`
	Pprof     pprof.Config   `yaml:"pprof,omitempty"`
	Metrics   metrics.Config `yaml:"metrics,omitempty"`

	Registration workerRegistration.Config `yaml:"registration,omitempty"`
	Keymanager   workerKM.Config           `yaml:"keymanager,omitempty"`
	Storage      workerStorage.Config      `yaml:"storage,omitempty"`
	Sentry       workerSentry.Config       `yaml:"sentry,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	var err error

	switch c.Mode {
	case ModeValidator:
	case ModeCompute:
	case ModeKeyManager:
	case ModeClient:
	case ModeStatelessClient:
	case ModeSeed:
	case ModeArchive:
	default:
		return fmt.Errorf("unknown node mode: %s", c.Mode)
	}

	if err = c.Common.Validate(); err != nil {
		return fmt.Errorf("common: %w", err)
	}
	if err = c.Genesis.Validate(); err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	if err = c.Consensus.Validate(); err != nil {
		return fmt.Errorf("tendermint: %w", err)
	}
	if err = c.Runtime.Validate(); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	if err = c.P2P.Validate(); err != nil {
		return fmt.Errorf("p2p: %w", err)
	}
	if err = c.Registration.Validate(); err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	if err = c.Keymanager.Validate(); err != nil {
		return fmt.Errorf("keymanager: %w", err)
	}
	if err = c.Storage.Validate(); err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	if err = c.Sentry.Validate(); err != nil {
		return fmt.Errorf("sentry: %w", err)
	}
	if err = c.IAS.Validate(); err != nil {
		return fmt.Errorf("ias: %w", err)
	}
	if err = c.Pprof.Validate(); err != nil {
		return fmt.Errorf("pprof: %w", err)
	}
	if err = c.Metrics.Validate(); err != nil {
		return fmt.Errorf("metrics: %w", err)
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Mode:         ModeClient,
		Common:       common.DefaultConfig(),
		Genesis:      genesis.DefaultConfig(),
		Consensus:    tm.DefaultConfig(),
		Runtime:      runtime.DefaultConfig(),
		P2P:          p2p.DefaultConfig(),
		Registration: workerRegistration.DefaultConfig(),
		Keymanager:   workerKM.DefaultConfig(),
		Storage:      workerStorage.DefaultConfig(),
		Sentry:       workerSentry.DefaultConfig(),
		IAS:          ias.DefaultConfig(),
		Pprof:        pprof.DefaultConfig(),
		Metrics:      metrics.DefaultConfig(),
	}
}

// InitConfig initializes the global configuration from the given file.
func InitConfig(cfgFile string) error {
	// Read the specified config file and substitute environment variables.
	cfg, err := envsubst.ReadFile(cfgFile)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", cfgFile, err)
	}

	// Reset the global config and apply changes from the config file.
	// Report error if any of the fields from the input file are unknown.
	GlobalConfig = DefaultConfig()
	dec := yaml.NewDecoder(bytes.NewReader(cfg))
	dec.KnownFields(true)
	err = dec.Decode(&GlobalConfig)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to load config file '%s': %w", cfgFile, err)
	}

	// Validate config file.
	return GlobalConfig.Validate()
}

func init() {
	GlobalConfig = DefaultConfig()
}
