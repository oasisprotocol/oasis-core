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
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	rtConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	hostComposite "github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	hostLoadBalance "github.com/oasisprotocol/oasis-core/go/runtime/host/loadbalance"
	hostMock "github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	hostProtocol "github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	hostSandbox "github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	hostSgx "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
	hostTdx "github.com/oasisprotocol/oasis-core/go/runtime/host/tdx"
)

const (
	// CfgDebugMockIDs configures mock runtime IDs for the purpose
	// of testing.
	CfgDebugMockIDs = "runtime.debug.mock_ids"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// newRuntimeConfig creates a new node runtime configuration.
func newRuntimeConfig(dataDir string) (map[common.Namespace]map[version.Version]*runtimeHost.Config, error) { //nolint: gocyclo
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
	runtimes := make(map[common.Namespace]map[version.Version]*runtimeHost.Config)

	if haveSetRuntimes || (cmdFlags.DebugDontBlameOasis() && viper.IsSet(CfgDebugMockIDs)) {
		// By default start with the environment specified in configuration.
		runtimeEnv := config.GlobalConfig.Runtime.Environment

		// Preprocess runtimes to separate detached from non-detached.
		type nameKey struct {
			runtime common.Namespace
			comp    component.ID
		}

		var (
			regularBundles []*bundle.Bundle
			err            error
		)
		detachedBundles := make(map[common.Namespace][]*bundle.Bundle)
		existingNames := make(map[nameKey]struct{})
		for _, path := range config.GlobalConfig.Runtime.Paths {
			var bnd *bundle.Bundle
			if bnd, err = bundle.Open(path); err != nil {
				return nil, fmt.Errorf("failed to load runtime bundle '%s': %w", path, err)
			}
			if _, err = bnd.WriteExploded(dataDir); err != nil {
				return nil, fmt.Errorf("failed to explode runtime bundle '%s': %w", path, err)
			}
			// Release resources as the bundle has been exploded anyway.
			bnd.Data = nil

			switch bnd.Manifest.IsDetached() {
			case false:
				// A regular non-detached bundle that has the RONL component.
				regularBundles = append(regularBundles, bnd)
			case true:
				// A detached bundle without the RONL component that needs to be attached.
				detachedBundles[bnd.Manifest.ID] = append(detachedBundles[bnd.Manifest.ID], bnd)

				// Ensure there are no name conflicts among the components.
				for compID := range bnd.Manifest.GetAvailableComponents() {
					nk := nameKey{bnd.Manifest.ID, compID}
					if _, ok := existingNames[nk]; ok {
						return nil, fmt.Errorf("duplicate component '%s' for runtime '%s'", compID, bnd.Manifest.ID)
					}
					existingNames[nk] = struct{}{}
				}
			}

			// If the runtime environment is set to automatic selection and a bundle has a component
			// that requires the use of a TEE, force a TEE environment to simplify configuration.
			if runtimeEnv == rtConfig.RuntimeEnvironmentAuto {
				for _, comp := range bnd.Manifest.GetAvailableComponents() {
					if comp.IsTEERequired() {
						runtimeEnv = rtConfig.RuntimeEnvironmentSGX
						break
					}
				}
			}
		}

		// Configure runtimes.
		for _, bnd := range regularBundles {
			id := bnd.Manifest.ID
			if runtimes[id] == nil {
				runtimes[id] = make(map[version.Version]*runtimeHost.Config)
			}
			version := bnd.Manifest.GetComponentByID(component.ID_RONL).Version
			if _, ok := runtimes[id][version]; ok {
				return nil, fmt.Errorf("duplicate runtime '%s' version '%s'", id, bnd.Manifest.Version)
			}

			// Get any local runtime configuration.
			var localConfig map[string]interface{}
			if lc, ok := config.GlobalConfig.Runtime.RuntimeConfig[id.String()]; ok {
				localConfig = lc
			}

			rtBnd := &runtimeHost.RuntimeBundle{
				Bundle:               bnd,
				ExplodedDataDir:      dataDir,
				ExplodedDetachedDirs: make(map[component.ID]string),
			}

			// Merge in detached components.
			for _, detachedBnd := range detachedBundles[id] {
				for _, detachedComp := range detachedBnd.Manifest.Components {
					// Skip components that already exist in the bundle itself.
					if bnd.Manifest.GetComponentByID(detachedComp.ID()) != nil {
						continue
					}

					bnd.Manifest.Components = append(bnd.Manifest.Components, detachedComp)
					rtBnd.ExplodedDetachedDirs[detachedComp.ID()] = detachedBnd.ExplodedPath(dataDir, "")
				}
			}

			// Determine what kind of components we want.
			wantedComponents := []component.ID{
				component.ID_RONL,
			}
			for _, comp := range bnd.Manifest.Components {
				if comp.ID().IsRONL() {
					continue // Always enabled above.
				}

				// By default honor the status of the component itself.
				enabled := !comp.Disabled
				// On non-compute nodes, assume all components are disabled by default.
				if config.GlobalConfig.Mode != config.ModeCompute {
					enabled = false
				}
				// Detached components are explicit and they should be enabled by default.
				if _, ok := rtBnd.ExplodedDetachedDirs[comp.ID()]; ok {
					enabled = true
				}

				// Check for any overrides in the node configuration.
				compCfg, ok := config.GlobalConfig.Runtime.GetComponent(comp.ID())
				if ok {
					enabled = !compCfg.Disabled
				}

				if !enabled {
					continue
				}

				wantedComponents = append(wantedComponents, comp.ID())
			}

			runtimes[id][version] = &runtimeHost.Config{
				Bundle:      rtBnd,
				Components:  wantedComponents,
				LocalConfig: localConfig,
			}
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
								Components: []*bundle.Component{
									{
										Kind:       component.RONL,
										Executable: "mock",
									},
								},
							},
						},
					},
					Components: []component.ID{
						component.ID_RONL,
					},
				}
				runtimes[id] = map[version.Version]*runtimeHost.Config{
					{}: runtimeHostCfg,
				}
			}
		}

		if len(runtimes) == 0 {
			return nil, fmt.Errorf("no runtimes configured")
		}
	}

	return runtimes, nil
}

func createHostInfo(consensus consensus.Backend) (*hostProtocol.HostInfo, error) {
	cs, err := consensus.GetStatus(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus layer status: %w", err)
	}

	chainCtx, err := consensus.GetChainContext(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain context: %w", err)
	}

	return &hostProtocol.HostInfo{
		ConsensusBackend:         cs.Backend,
		ConsensusProtocolVersion: cs.Version,
		ConsensusChainContext:    chainCtx,
	}, nil
}

func createProvisioner(
	commonStore *persistent.CommonStore,
	identity *identity.Identity,
	consensus consensus.Backend,
	hostInfo *hostProtocol.HostInfo,
	ias []ias.Endpoint,
	qs pcs.QuoteService,
) (runtimeHost.Provisioner, error) {
	var err error

	// By default start with the environment specified in configuration.
	runtimeEnv := config.GlobalConfig.Runtime.Environment

	// TODO: isEnvSGX should also be true if runtimeEnv is auto and at least
	// one component requires SGX.
	isEnvSGX := runtimeEnv == rtConfig.RuntimeEnvironmentSGX || runtimeEnv == rtConfig.RuntimeEnvironmentSGXMock
	forceNoSGX := (config.GlobalConfig.Mode.IsClientOnly() && !isEnvSGX) ||
		(cmdFlags.DebugDontBlameOasis() && runtimeEnv == rtConfig.RuntimeEnvironmentELF)

	// Register provisioners based on the configured provisioner.
	var insecureNoSandbox bool
	sandboxBinary := config.GlobalConfig.Runtime.SandboxBinary
	attestInterval := config.GlobalConfig.Runtime.AttestInterval
	provisioners := make(map[component.TEEKind]runtimeHost.Provisioner)
	switch p := config.GlobalConfig.Runtime.Provisioner; p {
	case rtConfig.RuntimeProvisionerMock:
		// Mock provisioner, only supported when the runtime requires no TEE hardware.
		if !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("mock provisioner requires use of unsafe debug flags")
		}

		provisioners[component.TEEKindNone] = hostMock.New()
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
		provisioners[component.TEEKindNone], err = hostSandbox.New(hostSandbox.Config{
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
			provisioners[component.TEEKindSGX], err = hostSandbox.New(hostSandbox.Config{
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
		case sgxLoader == "" && runtimeEnv != rtConfig.RuntimeEnvironmentSGXMock:
			// SGX may be needed, but we don't have a loader configured.
			break
		default:
			// Configure mock SGX if configured and we are in a debug mode.
			insecureMock := runtimeEnv == rtConfig.RuntimeEnvironmentSGXMock
			if insecureMock && !cmdFlags.DebugDontBlameOasis() {
				return nil, fmt.Errorf("mock SGX requires use of unsafe debug flags")
			}

			provisioners[component.TEEKindSGX], err = hostSgx.New(hostSgx.Config{
				HostInfo:              hostInfo,
				CommonStore:           commonStore,
				LoaderPath:            sgxLoader,
				IAS:                   ias,
				PCS:                   qs,
				Consensus:             consensus,
				Identity:              identity,
				SandboxBinaryPath:     sandboxBinary,
				InsecureNoSandbox:     insecureNoSandbox,
				InsecureMock:          insecureMock,
				RuntimeAttestInterval: attestInterval,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create SGX runtime provisioner: %w", err)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported runtime provisioner: %s", p)
	}

	// Configure TDX provisioner.
	// TODO: Allow provisioner selection in the future, currently we only have QEMU.
	provisioners[component.TEEKindTDX], err = hostTdx.NewQemu(hostTdx.QemuConfig{
		HostInfo:              hostInfo,
		CommonStore:           commonStore,
		PCS:                   qs,
		Consensus:             consensus,
		Identity:              identity,
		RuntimeAttestInterval: attestInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX runtime provisioner: %w", err)
	}

	// Configure optional load balancing.
	for tee, rp := range provisioners {
		provisioners[tee] = hostLoadBalance.New(rp, hostLoadBalance.Config{
			NumInstances: int(config.GlobalConfig.Runtime.LoadBalancer.NumInstances),
		})
	}

	// Create a composite provisioner to provision the individual components.
	provisioner := hostComposite.NewProvisioner(provisioners)

	return provisioner, nil
}

func createCachingQuoteService(commonStore *persistent.CommonStore) (pcs.QuoteService, error) {
	pc, err := pcs.NewHTTPClient(&pcs.HTTPClientConfig{
		// TODO: Support configuring the API key.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PCS HTTP client: %w", err)
	}

	qs := pcs.NewCachingQuoteService(pc, commonStore)

	return qs, nil
}

func createHistoryFactory() (history.Factory, error) {
	var pruneFactory history.PrunerFactory
	strategy := config.GlobalConfig.Runtime.Prune.Strategy
	switch strings.ToLower(strategy) {
	case history.PrunerStrategyNone:
		pruneFactory = history.NewNonePrunerFactory()
	case history.PrunerStrategyKeepLast:
		numKept := config.GlobalConfig.Runtime.Prune.NumKept
		pruneInterval := max(config.GlobalConfig.Runtime.Prune.Interval, time.Second)
		pruneFactory = history.NewKeepLastPrunerFactory(numKept, pruneInterval)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	// Archive node won't commit any new blocks, so disable waiting for storage
	// sync commits.
	mode := config.GlobalConfig.Mode
	hasLocalStorage := mode.HasLocalStorage() && !mode.IsArchive()

	historyFactory := history.NewFactory(pruneFactory, hasLocalStorage)

	return historyFactory, nil
}

func init() {
	Flags.StringSlice(CfgDebugMockIDs, nil, "Mock runtime IDs (format: <path>,<path>,...)")
	_ = Flags.MarkHidden(CfgDebugMockIDs)

	_ = viper.BindPFlags(Flags)
}
