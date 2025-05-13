// Package sandbox implements the runtime provisioner for runtimes in sandboxed processes.
package sandbox

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
)

// GetSandboxConfigFunc is the function used to generate the sandbox configuration.
type GetSandboxConfigFunc func(cfg host.Config, conn Connector, runtimeDir string) (process.Config, error)

// CleanupFunc is the runtime cleanup function.
type CleanupFunc func(cfg host.Config)

// Config contains the sandbox provisioner configuration options.
type Config struct {
	// Connector is the runtime connector factory that is used to establish a connection with the
	// runtime via the Runtime Host Protocol.
	Connector ConnectorFactoryFunc

	// GetSandboxConfig is a function that generates the sandbox configuration. In case it is not
	// specified a default function is used.
	GetSandboxConfig GetSandboxConfigFunc

	// Cleanup is a function that gets called when the runtime is cleaned up.
	Cleanup CleanupFunc

	// HostInfo provides information about the host environment.
	HostInfo *protocol.HostInfo

	// HostInitializer is a function that additionally initializes the runtime host. In case it is
	// not specified a default function is used.
	HostInitializer func(context.Context, *HostInitializerParams) (*host.StartedEvent, error)

	// Logger is an optional logger to use with this provisioner. In case it is not specified a
	// default logger will be created.
	Logger *logging.Logger

	// SandboxBinaryPath is the path to the sandbox support binary.
	SandboxBinaryPath string

	// InsecureNoSandbox disables the sandbox and runs the runtime binary directly.
	InsecureNoSandbox bool
}

type sandboxProvisioner struct {
	cfg Config
}

// NewProvisioner creates a new runtime provisioner that uses a local process sandbox.
func NewProvisioner(cfg Config) (host.Provisioner, error) {
	// Use a default Logger if none was provided.
	if cfg.Logger == nil {
		cfg.Logger = logging.GetLogger("runtime/host/sandbox")
	}
	// Use a default Connector if none was provided.
	if cfg.Connector == nil {
		cfg.Connector = NewUnixSocketConnector
	}
	// Use a default GetSandboxConfig if none was provided.
	if cfg.GetSandboxConfig == nil {
		cfg.GetSandboxConfig = DefaultGetSandboxConfig(cfg.Logger, cfg.SandboxBinaryPath)
	}
	// Use a default Cleanup if none was provided.
	if cfg.Cleanup == nil {
		cfg.Cleanup = func(host.Config) {}
	}
	// Make sure host environment information was provided in HostInfo.
	if cfg.HostInfo == nil {
		return nil, fmt.Errorf("no host information provided")
	}
	// Use a default HostInitializer if none was provided.
	if cfg.HostInitializer == nil {
		cfg.HostInitializer = func(_ context.Context, hp *HostInitializerParams) (*host.StartedEvent, error) {
			return &host.StartedEvent{
				Version: hp.Version,
			}, nil
		}
	}
	return &sandboxProvisioner{cfg: cfg}, nil
}

// Implements host.Provisioner.
func (p *sandboxProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	return &sandboxHost{
		cfg:                         p.cfg,
		rtCfg:                       cfg,
		id:                          cfg.ID,
		startOne:                    cmSync.NewOne(),
		ctrlCh:                      make(chan any, ctrlChannelBufferSize),
		notifier:                    pubsub.NewBroker(false),
		notifyUpdateCapabilityTEECh: make(chan struct{}, 1),
		logger:                      p.cfg.Logger.With("runtime_id", cfg.ID),
	}, nil
}

// Implements host.Provisioner.
func (p *sandboxProvisioner) Name() string {
	return "sandbox"
}

// DefaultGetSandboxConfig is the default function for generating sandbox configuration.
func DefaultGetSandboxConfig(logger *logging.Logger, sandboxBinaryPath string) GetSandboxConfigFunc {
	return func(cfg host.Config, _ Connector, _ string) (process.Config, error) {
		logWrapper := host.NewRuntimeLogWrapper(
			logger,
			cfg.Log.Logger(),
			"runtime_id", cfg.ID,
			"runtime_name", cfg.Name,
			"component", cfg.Component.ID(),
			"provisioner", "sandbox",
		)

		executable := cfg.Component.Executable
		if cfg.Component.ELF != nil {
			executable = cfg.Component.ELF.Executable
		}

		return process.Config{
			Path:              cfg.Component.ExplodedPath(executable),
			SandboxBinaryPath: sandboxBinaryPath,
			Stdout:            logWrapper,
			Stderr:            logWrapper,
			AllowNetwork:      cfg.Component.IsNetworkAllowed(),
		}, nil
	}
}
