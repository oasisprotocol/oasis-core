package registry

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
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

func getLocalConfig(runtimeID common.Namespace) map[string]interface{} {
	return config.GlobalConfig.Runtime.GetLocalConfig(runtimeID)
}

func getConfiguredRuntimeIDs(registry bundle.Registry) ([]common.Namespace, error) {
	// Check if any runtimes are configured to be hosted.
	runtimes := make(map[common.Namespace]struct{})
	for _, cfg := range config.GlobalConfig.Runtime.Runtimes {
		runtimes[cfg.ID] = struct{}{}
	}

	// Support legacy configurations where runtimes are specified within
	// configured bundles.
	for _, manifest := range registry.GetManifests() {
		runtimes[manifest.ID] = struct{}{}
	}

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(bundle.CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		for _, str := range viper.GetStringSlice(bundle.CfgDebugMockIDs) {
			var runtimeID common.Namespace
			if err := runtimeID.UnmarshalText([]byte(str)); err != nil {
				return nil, fmt.Errorf("failed to deserialize runtime ID: %w", err)
			}
			runtimes[runtimeID] = struct{}{}
		}

		// Skip validation
		return slices.Collect(maps.Keys(runtimes)), nil
	}

	// Validate configured runtimes based on the runtime mode.
	switch config.GlobalConfig.Mode {
	case config.ModeValidator, config.ModeSeed:
		// No runtimes should be configured.
		if len(runtimes) > 0 && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("no runtimes should be configured when in validator or seed modes")
		}
	case config.ModeCompute, config.ModeKeyManager, config.ModeStatelessClient:
		// At least one runtime should be configured.
		if len(runtimes) == 0 && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("at least one runtime must be configured when in compute, keymanager, or client-stateless modes")
		}
	default:
		// In any other mode, runtimes can be optionally configured.
	}

	return slices.Collect(maps.Keys(runtimes)), nil
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
	var insecureNoSandbox bool

	attestInterval := config.GlobalConfig.Runtime.AttestInterval
	sandboxBinary := config.GlobalConfig.Runtime.SandboxBinary
	sgxLoader := config.GlobalConfig.Runtime.SGXLoader
	runtimeEnv := config.GlobalConfig.Runtime.Environment

	// Register provisioners based on the configured provisioner.
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
		insecureMock := runtimeEnv == rtConfig.RuntimeEnvironmentSGXMock
		if insecureMock && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("mock SGX requires use of unsafe debug flags")
		}

		if !insecureMock && sgxLoader == "" {
			// SGX may be needed, but we don't have a loader configured.
			break
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
