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
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	rtConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	hostLoadBalance "github.com/oasisprotocol/oasis-core/go/runtime/host/loadbalance"
	hostMock "github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	hostProtocol "github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	hostSandbox "github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	hostSgx "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
)

const (
	// CfgDebugMockIDs configures mock runtime IDs for the purpose
	// of testing.
	CfgDebugMockIDs = "runtime.debug.mock_ids"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// RuntimeConfig is the node runtime configuration.
type RuntimeConfig struct {
	// Host contains configuration for the runtime host. It may be nil if no runtimes are to be
	// hosted by the current node.
	Host *RuntimeHostConfig

	// History configures the runtime history keeper.
	History history.Config
}

// Runtimes returns a list of configured runtimes.
func (cfg *RuntimeConfig) Runtimes() (runtimes []common.Namespace) {
	if cfg.Host == nil || config.GlobalConfig.Mode == config.ModeKeyManager {
		return
	}

	for id := range cfg.Host.Runtimes {
		runtimes = append(runtimes, id)
	}
	return
}

// RuntimeHostConfig is configuration for a node that hosts runtimes.
type RuntimeHostConfig struct {
	// Provisioners contains a set of supported runtime provisioners, based on TEE hardware.
	Provisioners map[node.TEEHardware]runtimeHost.Provisioner

	// Runtimes contains per-runtime provisioning configuration. Some fields may be omitted as they
	// are provided when the runtime is provisioned.
	Runtimes map[common.Namespace]map[version.Version]*runtimeHost.Config
}

func newConfig(dataDir string, commonStore *persistent.CommonStore, consensus consensus.Backend, ias []ias.Endpoint) (*RuntimeConfig, error) { //nolint: gocyclo
	var cfg RuntimeConfig

	haveSetRuntimes := len(config.GlobalConfig.Runtime.Paths) > 0

	// Validate configured runtimes based on the runtime mode.
	switch config.GlobalConfig.Mode {
	case config.ModeValidator, config.ModeSeed:
		// No runtimes should be configured.
		if haveSetRuntimes && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("no runtimes should be configured when in validator or seed modes")
		}
	case config.ModeCompute, config.ModeKeyManager, config.ModeStatelessClient:
		// At least one runtime should be configured.
		if !haveSetRuntimes && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("at least one runtime must be configured when in compute, keymanager, or client-stateless modes")
		}
	default:
		// In any other mode, runtimes can be optionally configured.
	}

	// Check if any runtimes are configured to be hosted.
	if haveSetRuntimes || (cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs)) {
		runtimeEnv := config.GlobalConfig.Runtime.Environment
		forceNoSGX := (config.GlobalConfig.Mode.IsClientOnly() && runtimeEnv != rtConfig.RuntimeEnvironmentSGX) ||
			(cmdFlags.DebugDontBlameOasis() && runtimeEnv == rtConfig.RuntimeEnvironmentELF)

		var rh RuntimeHostConfig

		// Configure host environment information.
		cs, err := consensus.GetStatus(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get consensus layer status: %w", err)
		}
		chainCtx, err := consensus.GetChainContext(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get chain context: %w", err)
		}
		hostInfo := &hostProtocol.HostInfo{
			ConsensusBackend:         cs.Backend,
			ConsensusProtocolVersion: cs.Version,
			ConsensusChainContext:    chainCtx,
		}

		// Register provisioners based on the configured provisioner.
		var insecureNoSandbox bool
		sandboxBinary := config.GlobalConfig.Runtime.SandboxBinary
		attestInterval := config.GlobalConfig.Runtime.AttestInterval
		rh.Provisioners = make(map[node.TEEHardware]runtimeHost.Provisioner)
		switch p := config.GlobalConfig.Runtime.Provisioner; p {
		case rtConfig.RuntimeProvisionerMock:
			// Mock provisioner, only supported when the runtime requires no TEE hardware.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("mock provisioner requires use of unsafe debug flags")
			}

			rh.Provisioners[node.TEEHardwareInvalid] = hostMock.New()
		case rtConfig.RuntimeProvisionerUnconfined:
			// Unconfined provisioner, can be used with no TEE or with Intel SGX.
			if !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("unconfined provisioner requires use of unsafe debug flags")
			}

			insecureNoSandbox = true

			fallthrough
		case rtConfig.RuntimeProvisionerSandboxed:
			// Sandboxed provisioner, can be used with no TEE or with Intel SGX.
			if !insecureNoSandbox {
				if _, err = os.Stat(sandboxBinary); err != nil {
					return nil, fmt.Errorf("failed to stat sandbox binary: %w", err)
				}
			}

			// Configure the non-TEE provisioner.
			rh.Provisioners[node.TEEHardwareInvalid], err = hostSandbox.New(hostSandbox.Config{
				HostInfo:          hostInfo,
				InsecureNoSandbox: insecureNoSandbox,
				SandboxBinaryPath: sandboxBinary,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create runtime provisioner: %w", err)
			}

			// Configure the Intel SGX provisioner.
			switch sgxLoader := config.GlobalConfig.Runtime.SGXLoader; {
			case forceNoSGX:
				// Remap SGX to non-SGX when forced to do so.
				rh.Provisioners[node.TEEHardwareIntelSGX], err = hostSandbox.New(hostSandbox.Config{
					HostInfo:          hostInfo,
					InsecureNoSandbox: insecureNoSandbox,
					SandboxBinaryPath: sandboxBinary,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create runtime provisioner: %w", err)
				}
			case sgxLoader == "" && runtimeEnv == rtConfig.RuntimeEnvironmentSGX:
				// SGX environment is forced, but we don't have the needed loader.
				return nil, fmt.Errorf("SGX runtime environment requires setting the SGX loader")
			case sgxLoader == "":
				// SGX may be needed, but we don't have a loader configured.
				break
			default:
				// Configure the provided SGX loader.
				var pc pcs.Client
				pc, err = pcs.NewHTTPClient(&pcs.HTTPClientConfig{
					// TODO: Support configuring the API key.
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create PCS HTTP client: %w", err)
				}

				rh.Provisioners[node.TEEHardwareIntelSGX], err = hostSgx.New(hostSgx.Config{
					HostInfo:              hostInfo,
					CommonStore:           commonStore,
					LoaderPath:            sgxLoader,
					IAS:                   ias,
					PCS:                   pc,
					Consensus:             consensus,
					SandboxBinaryPath:     sandboxBinary,
					InsecureNoSandbox:     insecureNoSandbox,
					RuntimeAttestInterval: attestInterval,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create SGX runtime provisioner: %w", err)
				}
			}
		default:
			return nil, fmt.Errorf("unsupported runtime provisioner: %s", p)
		}

		// Configure optional load balancing.
		for tee, rp := range rh.Provisioners {
			rh.Provisioners[tee] = hostLoadBalance.New(rp, hostLoadBalance.Config{
				NumInstances: int(config.GlobalConfig.Runtime.LoadBalancer.NumInstances),
			})
		}

		// Configure runtimes.
		rh.Runtimes = make(map[common.Namespace]map[version.Version]*runtimeHost.Config)
		for _, path := range config.GlobalConfig.Runtime.Paths {
			// Open and explode the bundle.  This will call Validate().
			var bnd *bundle.Bundle
			if bnd, err = bundle.Open(path); err != nil {
				return nil, fmt.Errorf("failed to load runtime bundle '%s': %w", path, err)
			}
			if err = bnd.WriteExploded(dataDir); err != nil {
				return nil, fmt.Errorf("failed to explode runtime bundle '%s': %w", path, err)
			}

			id := bnd.Manifest.ID
			if rh.Runtimes[id] == nil {
				rh.Runtimes[id] = make(map[version.Version]*runtimeHost.Config)
			}

			// Get any local runtime configuration.
			var localConfig map[string]interface{}
			if config.GlobalConfig.Runtime.RuntimeConfig != nil {
				if lcRaw, ok := config.GlobalConfig.Runtime.RuntimeConfig[id.String()]; ok {
					if lc, ok := lcRaw.(map[string]interface{}); ok {
						localConfig = lc
					} else {
						return nil, fmt.Errorf("malformed runtime configuration for runtime %s", id.String())
					}
				}
			}

			runtimeHostCfg := &runtimeHost.Config{
				Bundle: &runtimeHost.RuntimeBundle{
					Bundle: bnd,
					Path:   bnd.ExplodedPath(dataDir, bnd.Manifest.Executable),
				},
				LocalConfig: localConfig,
			}

			var haveSGXSignature bool
			if !forceNoSGX && bnd.Manifest.SGX != nil {
				// Ensure SGX provisioner is configured.
				if _, ok := rh.Provisioners[node.TEEHardwareIntelSGX]; !ok {
					return nil, fmt.Errorf("SGX loader binary path is not configured")
				}

				// If this is a TEE enclave, override the executable to point
				// at the enclave binary instead.
				runtimeHostCfg.Bundle.Path = bnd.ExplodedPath(dataDir, bnd.Manifest.SGX.Executable)
				if bnd.Manifest.SGX.Signature != "" {
					haveSGXSignature = true
					runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
						SignaturePath: bnd.ExplodedPath(dataDir, bnd.Manifest.SGX.Signature),
					}
				}
			}
			if !haveSGXSignature {
				// HACK HACK HACK: Allow dummy SIGSTRUCT generation.
				runtimeHostCfg.Extra = &hostSgx.RuntimeExtra{
					UnsafeDebugGenerateSigstruct: true,
				}
			}

			rh.Runtimes[id][bnd.Manifest.Version] = runtimeHostCfg
		}
		if cmdFlags.DebugDontBlameOasis() {
			// This is to allow the mock provisioner to function, as it does
			// not use an actual runtime, thus is missing a bundle.  This is
			// only used for the basic node tests.
			for _, idStr := range viper.GetStringSlice(CfgDebugMockIDs) {
				var id common.Namespace
				if err = id.UnmarshalText([]byte(idStr)); err != nil {
					return nil, fmt.Errorf("failed to deserialize runtime ID: %w", err)
				}

				runtimeHostCfg := &runtimeHost.Config{
					Bundle: &runtimeHost.RuntimeBundle{
						Bundle: &bundle.Bundle{
							Manifest: &bundle.Manifest{
								ID: id,
							},
						},
					},
				}
				rh.Runtimes[id] = map[version.Version]*runtimeHost.Config{
					{}: runtimeHostCfg,
				}
			}
		}
		if len(rh.Runtimes) == 0 {
			return nil, fmt.Errorf("no runtimes configured")
		}

		cfg.Host = &rh
	}

	strategy := config.GlobalConfig.Runtime.Prune.Strategy
	switch strings.ToLower(strategy) {
	case history.PrunerStrategyNone:
		cfg.History.Pruner = history.NewNonePruner()
	case history.PrunerStrategyKeepLast:
		numKept := config.GlobalConfig.Runtime.Prune.NumKept
		cfg.History.Pruner = history.NewKeepLastPruner(numKept)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	cfg.History.PruneInterval = config.GlobalConfig.Runtime.Prune.Interval
	const minPruneInterval = 1 * time.Second
	if cfg.History.PruneInterval < minPruneInterval {
		cfg.History.PruneInterval = minPruneInterval
	}

	return &cfg, nil
}

func init() {
	Flags.StringSlice(CfgDebugMockIDs, nil, "Mock runtime IDs (format: <path>,<path>,...)")
	_ = Flags.MarkHidden(CfgDebugMockIDs)

	_ = viper.BindPFlags(Flags)
}
