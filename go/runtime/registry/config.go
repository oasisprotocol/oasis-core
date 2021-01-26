package registry

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	hostMock "github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	hostProtocol "github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	hostSandbox "github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	hostSgx "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
	"github.com/oasisprotocol/oasis-core/go/runtime/tagindexer"
)

const (
	// CfgSupported configures a supported runtime ID.
	CfgSupported = "runtime.supported"

	// CfgRuntimeProvisioner configures the runtime provisioner.
	//
	// The same provisioner is used for all runtimes.
	CfgRuntimeProvisioner = "runtime.provisioner"
	// CfgRuntimePaths confgures the paths for supported runtimes.
	//
	// The value should be a map of runtime IDs to corresponding resource paths (type of the
	// resource depends on the provisioner).
	CfgRuntimePaths = "runtime.paths"
	// CfgSandboxBinary configures the runtime sandbox binary location.
	CfgSandboxBinary = "runtime.sandbox.binary"
	// CfgRuntimeSGXLoader configures the runtime loader binary required for SGX runtimes.
	//
	// The same loader is used for all runtimes.
	CfgRuntimeSGXLoader = "runtime.sgx.loader"
	// CfgRuntimeSGXSignatures configures signatures for supported runtimes.
	//
	// The value should be a map of runtime IDs to corresponding resource paths.
	CfgRuntimeSGXSignatures = "runtime.sgx.signatures"

	// CfgHistoryPrunerStrategy configures the history pruner strategy.
	CfgHistoryPrunerStrategy = "runtime.history.pruner.strategy"
	// CfgHistoryPrunerInterval configures the history pruner interval.
	CfgHistoryPrunerInterval = "runtime.history.pruner.interval"
	// CfgHistoryPrunerKeepLastNum configures the number of last kept
	// rounds when using the "keep last" pruner strategy.
	CfgHistoryPrunerKeepLastNum = "runtime.history.pruner.num_kept"

	// CfgTagIndexerBackend configures the history tag indexer backend.
	CfgTagIndexerBackend = "runtime.history.tag_indexer.backend"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

const (
	// RuntimeProvisionerMock is the name of the mock runtime provisioner.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerMock = "mock"
	// RuntimeProvisionerUnconfined is the name of the unconfined runtime provisioner that executes
	// runtimes as regular processes without any sandboxing.
	//
	// Use of this provisioner is only allowed if DebugDontBlameOasis flag is set.
	RuntimeProvisionerUnconfined = "unconfined"
	// RuntimeProvisionerSandboxed is the name of the sandboxed runtime provisioner that executes
	// runtimes as regular processes in a Linux namespaces/cgroups/SECCOMP sandbox.
	RuntimeProvisionerSandboxed = "sandboxed"
)

// RuntimeConfig is the node runtime configuration.
type RuntimeConfig struct {
	// Host contains configuration for the runtime host. It may be nil if no runtimes are to be
	// hosted by the current node.
	Host *RuntimeHostConfig

	// History configures the runtime history keeper.
	History history.Config

	// TagIndexer configures the tag indexer backend.
	TagIndexer tagindexer.BackendFactory
}

// RuntimeHostConfig is configuration for a node that hosts runtimes.
type RuntimeHostConfig struct {
	// Provisioners contains a set of supported runtime provisioners, based on TEE hardware.
	Provisioners map[node.TEEHardware]runtimeHost.Provisioner

	// Runtimes contains per-runtime provisioning configuration. Some fields may be omitted as they
	// are provided when the runtime is provisioned.
	Runtimes map[common.Namespace]*runtimeHost.Config
}

func newConfig(consensus consensus.Backend, ias ias.Endpoint) (*RuntimeConfig, error) {
	var cfg RuntimeConfig

	// Check if any runtimes are configured to be hosted.
	if viper.IsSet(CfgRuntimePaths) {
		var rh RuntimeHostConfig

		// Configure host environment information.
		cs, err := consensus.GetStatus(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get consensus layer status: %w", err)
		}
		hostInfo := &hostProtocol.HostInfo{
			ConsensusBackend:         cs.Backend,
			ConsensusProtocolVersion: cs.Version.ToU64(),
		}

		// Register provisioners based on the configured provisioner.
		var insecureNoSandbox bool
		sandboxBinary := viper.GetString(CfgSandboxBinary)
		rh.Provisioners = make(map[node.TEEHardware]runtimeHost.Provisioner)
		switch p := viper.GetString(CfgRuntimeProvisioner); p {
		case RuntimeProvisionerMock:
			// Mock provisioner, only supported when the runtime requires no TEE hardware.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("mock provisioner requires use of unsafe debug flags")
			}

			rh.Provisioners[node.TEEHardwareInvalid] = hostMock.New()
		case RuntimeProvisionerUnconfined:
			// Unconfined provisioner, can be used with no TEE or with Intel SGX.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("unconfined provisioner requires use of unsafe debug flags")
			}

			insecureNoSandbox = true

			fallthrough
		case RuntimeProvisionerSandboxed:
			if !insecureNoSandbox {
				if _, err = os.Stat(sandboxBinary); err != nil {
					return nil, fmt.Errorf("failed to stat sandbox binary: %w", err)
				}
			}
			// Sandboxed provisioner, can be used with no TEE or with Intel SGX.
			rh.Provisioners[node.TEEHardwareInvalid], err = hostSandbox.New(hostSandbox.Config{
				HostInfo:          hostInfo,
				InsecureNoSandbox: insecureNoSandbox,
				SandboxBinaryPath: sandboxBinary,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create runtime provisioner: %w", err)
			}

			rh.Provisioners[node.TEEHardwareIntelSGX], err = hostSgx.New(hostSgx.Config{
				HostInfo:          hostInfo,
				LoaderPath:        viper.GetString(CfgRuntimeSGXLoader),
				IAS:               ias,
				SandboxBinaryPath: sandboxBinary,
				InsecureNoSandbox: insecureNoSandbox,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create SGX runtime provisioner: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported runtime provisioner: %s", p)
		}

		// Configure runtimes.
		runtimeSGXSignatures := viper.GetStringMapString(CfgRuntimeSGXSignatures)
		rh.Runtimes = make(map[common.Namespace]*runtimeHost.Config)
		for runtimeID, path := range viper.GetStringMapString(CfgRuntimePaths) {
			var id common.Namespace
			if err := id.UnmarshalHex(runtimeID); err != nil {
				return nil, fmt.Errorf("bad runtime identifier '%s': %w", runtimeID, err)
			}

			runtimeHostCfg := &runtimeHost.Config{
				RuntimeID: id,
				Path:      path,
			}

			// This config is SGX specific, but that's all that's supported
			// right now that needs this anyway, the non-SGX provisioner
			// currently ignores this.
			if sigPath := runtimeSGXSignatures[runtimeID]; sigPath != "" {
				runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
					SignaturePath: sigPath,
				}
			} else {
				// HACK HACK HACK: Allow dummy SIGSTRUCT generation.
				runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
					UnsafeDebugGenerateSigstruct: true,
				}
			}

			rh.Runtimes[id] = runtimeHostCfg
		}
		if len(rh.Runtimes) == 0 {
			return nil, fmt.Errorf("no runtimes configured")
		}

		cfg.Host = &rh
	}

	strategy := viper.GetString(CfgHistoryPrunerStrategy)
	switch strings.ToLower(strategy) {
	case history.PrunerStrategyNone:
		cfg.History.Pruner = history.NewNonePruner()
	case history.PrunerStrategyKeepLast:
		numKept := viper.GetUint64(CfgHistoryPrunerKeepLastNum)
		cfg.History.Pruner = history.NewKeepLastPruner(numKept)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	cfg.History.PruneInterval = viper.GetDuration(CfgHistoryPrunerInterval)
	if cfg.History.PruneInterval.Seconds() < 1.0 {
		return nil, fmt.Errorf("runtime/registry: history prune interval must be >= 1s (got %s)", cfg.History.PruneInterval)
	}

	tagIndexer := viper.GetString(CfgTagIndexerBackend)
	switch strings.ToLower(tagIndexer) {
	case "":
		cfg.TagIndexer = tagindexer.NewNopBackend()
	case tagindexer.BleveBackendName:
		cfg.TagIndexer = tagindexer.NewBleveBackend()
	default:
		return nil, fmt.Errorf("runtime/registry: unknown tag indexer backend: %s", tagIndexer)
	}

	return &cfg, nil
}

func init() {
	Flags.StringSlice(CfgSupported, nil, "Add supported runtime ID (hex-encoded)")

	Flags.String(CfgRuntimeProvisioner, RuntimeProvisionerSandboxed, "Runtime provisioner to use")
	Flags.StringToString(CfgRuntimePaths, nil, "Paths to runtime resources (format: <rt1-ID>=<path>,<rt2-ID>=<path>)")
	Flags.String(CfgSandboxBinary, "/usr/bin/bwrap", "Path to the sandbox binary (bubblewrap)")
	Flags.String(CfgRuntimeSGXLoader, "", "(for SGX runtimes) Path to SGXS runtime loader binary")
	Flags.StringToString(CfgRuntimeSGXSignatures, nil, "(for SGX runtimes) Paths to signatures (format: <rt1-ID>=<path>,<rt2-ID>=<path>")

	Flags.String(CfgHistoryPrunerStrategy, history.PrunerStrategyNone, "History pruner strategy")
	Flags.Duration(CfgHistoryPrunerInterval, 2*time.Minute, "History pruning interval")
	Flags.Uint64(CfgHistoryPrunerKeepLastNum, 600, "Keep last history pruner: number of last rounds to keep")

	Flags.String(CfgTagIndexerBackend, "", "Runtime tag indexer backend (disabled by default)")

	_ = viper.BindPFlags(Flags)
}
