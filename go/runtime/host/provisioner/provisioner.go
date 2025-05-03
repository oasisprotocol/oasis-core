package provisioner

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/ias"
	iasAPI "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	rtConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	runtimeHost "github.com/oasisprotocol/oasis-core/go/runtime/host"
	hostComposite "github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	hostLoadBalance "github.com/oasisprotocol/oasis-core/go/runtime/host/loadbalance"
	hostMock "github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	hostProtocol "github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	hostSandbox "github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	hostSgx "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx"
	hostTdx "github.com/oasisprotocol/oasis-core/go/runtime/host/tdx"
)

// New creates a new runtime provisioner.
//
// This helper function creates a provisioner capable of provisioning runtimes
// with or without a Trusted Execution Environment (TEE), such as Intel SGX
// or TDX. If the debug mock flag is enabled, the TEE will be mocked.
func New(
	dataDir string,
	commonStore *persistent.CommonStore,
	identity *identity.Identity,
	consensus consensus.Service,
) (runtimeHost.Provisioner, error) {
	// Initialize the IAS proxy client.
	ias, err := ias.New(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IAS proxy client: %w", err)
	}

	// Configure host environment information.
	hostInfo, err := createHostInfo(consensus)
	if err != nil {
		return nil, err
	}

	// Create the PCS client and quote service.
	qs, err := createCachingQuoteService(commonStore)
	if err != nil {
		return nil, err
	}

	// Create runtime provisioner.
	return createProvisioner(dataDir, commonStore, identity, consensus, hostInfo, ias, qs)
}

func createHostInfo(consensus consensus.Service) (*hostProtocol.HostInfo, error) {
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

func createProvisioner(
	dataDir string,
	commonStore *persistent.CommonStore,
	identity *identity.Identity,
	consensus consensus.Service,
	hostInfo *hostProtocol.HostInfo,
	ias []iasAPI.Endpoint,
	qs pcs.QuoteService,
) (runtimeHost.Provisioner, error) {
	var err error
	var insecureNoSandbox bool

	attestInterval := config.GlobalConfig.Runtime.AttestInterval
	sandboxBinary := config.GlobalConfig.Runtime.SandboxBinary
	sgxLoader := config.GlobalConfig.Runtime.SGX.Loader
	if sgxLoader == "" {
		sgxLoader = config.GlobalConfig.Runtime.SGXLoader
	}
	insecureMock := config.GlobalConfig.Runtime.DebugMockTEE

	// Support legacy configuration where the runtime environment determines
	// whether the TEE should be mocked.
	if config.GlobalConfig.Runtime.Environment == rtConfig.RuntimeEnvironmentSGXMock {
		insecureMock = true
	}

	// Register provisioners based on the configured provisioner.
	provisioners := make(map[component.TEEKind]runtimeHost.Provisioner)
	switch p := config.GlobalConfig.Runtime.Provisioner; p {
	case rtConfig.RuntimeProvisionerMock:
		// Mock provisioner, only supported when the runtime requires no TEE hardware.
		if !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("mock provisioner requires use of unsafe debug flags")
		}

		provisioners[component.TEEKindNone] = hostMock.NewProvisioner()
	case rtConfig.RuntimeProvisionerUnconfined:
		// Unconfined provisioner, can be used with no TEE or with Intel SGX.
		if !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("unconfined provisioner requires use of unsafe debug flags")
		}

		insecureNoSandbox = true

		fallthrough
	case rtConfig.RuntimeProvisionerSandboxed:
		// Sandboxed provisioner, can be used with no TEE or with Intel SGX.

		// Configure the non-TEE provisioner.
		provisioners[component.TEEKindNone], err = hostSandbox.NewProvisioner(hostSandbox.Config{
			HostInfo:          hostInfo,
			InsecureNoSandbox: insecureNoSandbox,
			SandboxBinaryPath: sandboxBinary,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime provisioner: %w", err)
		}

		// Configure the Intel SGX provisioner.
		if insecureMock && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("mock SGX requires use of unsafe debug flags")
		}

		if !insecureMock && sgxLoader == "" {
			// SGX may be needed, but we don't have a loader configured.
			break
		}

		provisioners[component.TEEKindSGX], err = hostSgx.NewProvisioner(hostSgx.Config{
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
	cidPool, err := hostTdx.NewCidPool(
		config.GlobalConfig.Runtime.TDX.CidStart,
		config.GlobalConfig.Runtime.TDX.CidCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CID pool: %w", err)
	}

	provisioners[component.TEEKindTDX], err = hostTdx.NewQemuProvisioner(hostTdx.QemuConfig{
		DataDir:               dataDir,
		HostInfo:              hostInfo,
		CommonStore:           commonStore,
		PCS:                   qs,
		Consensus:             consensus,
		Identity:              identity,
		CidPool:               cidPool,
		RuntimeAttestInterval: attestInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX runtime provisioner: %w", err)
	}

	// Configure optional load balancing.
	for tee, rp := range provisioners {
		numInstances := int(config.GlobalConfig.Runtime.LoadBalancer.NumInstances)
		provisioners[tee] = hostLoadBalance.NewProvisioner(rp, numInstances)
	}

	// Create a composite provisioner to provision the individual components.
	provisioner := hostComposite.NewProvisioner(provisioners)

	return provisioner, nil
}
