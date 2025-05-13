// Package sgx implements the runtime provisioner for runtimes in Intel SGX enclaves.
package sgx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/sigstruct"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
	sgxCommon "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
)

const (
	// TODO: Support different locations for the AESMD socket.
	aesmdSocketPath = "/var/run/aesmd/aesm.socket"

	sandboxMountRuntime   = "/runtime"
	sandboxMountSignature = "/runtime.sig"

	// Runtime RAK initialization timeout.
	//
	// This can take a long time in deployments that run multiple nodes on a single machine, all
	// sharing the same EPC. Additionally, this includes time to do the initial consensus light
	// client sync and freshness verification which can take some time.
	runtimeRAKTimeout = 5 * time.Minute
	// Runtime attest interval.
	defaultRuntimeAttestInterval = 2 * time.Hour
)

// Config contains SGX-specific provisioner configuration options.
type Config struct {
	// HostInfo provides information about the host environment.
	HostInfo *protocol.HostInfo

	// CommonStore is a handle to the node's common persistent store.
	CommonStore *persistent.CommonStore

	// LoaderPath is the path to the runtime loader binary.
	LoaderPath string

	// IAS are the Intel Attestation Service endpoint.
	IAS []ias.Endpoint
	// PCS is the Intel Provisioning Certification Service quote service.
	PCS pcs.QuoteService
	// Consensus is the consensus layer backend.
	Consensus consensus.Service
	// Identity is the node identity.
	Identity *identity.Identity

	// RuntimeAttestInterval is the interval for periodic runtime re-attestation. If not specified
	// a default will be used.
	RuntimeAttestInterval time.Duration

	// SandboxBinaryPath is the path to the sandbox support binary.
	SandboxBinaryPath string

	// InsecureNoSandbox disables the sandbox and runs the loader directly.
	InsecureNoSandbox bool
	// InsecureMock runs non-SGX binaries but treats it as if it would be running in an enclave,
	// using mock quotes and reports.
	//
	// This is useful in tests so most SGX code can be tested even on machines that lack SGX. Note
	// that this also requires quote verification to be skipped.
	InsecureMock bool
}

type sgxProvisioner struct {
	sync.Mutex

	cfg Config

	sandbox   host.Provisioner
	ias       []ias.Endpoint
	pcs       pcs.QuoteService
	aesm      *aesm.Client
	consensus consensus.Service
	identity  *identity.Identity
	store     *persistent.CommonStore

	logger *logging.Logger
}

// NewProvisioner creates a new Intel SGX runtime provisioner.
func NewProvisioner(cfg Config) (host.Provisioner, error) {
	// Use a default RuntimeAttestInterval if none was provided.
	if cfg.RuntimeAttestInterval == 0 {
		cfg.RuntimeAttestInterval = defaultRuntimeAttestInterval
	}

	sgxCommon.InitMetrics()

	p := &sgxProvisioner{
		cfg:       cfg,
		ias:       cfg.IAS,
		pcs:       cfg.PCS,
		aesm:      aesm.NewClient(aesmdSocketPath),
		consensus: cfg.Consensus,
		identity:  cfg.Identity,
		store:     cfg.CommonStore,
		logger:    logging.GetLogger("runtime/host/sgx"),
	}
	sp, err := sandbox.NewProvisioner(sandbox.Config{
		GetSandboxConfig:  p.getSandboxConfig,
		HostInfo:          cfg.HostInfo,
		HostInitializer:   p.hostInitializer,
		InsecureNoSandbox: cfg.InsecureNoSandbox,
		Logger:            p.logger,
	})
	if err != nil {
		return nil, err
	}
	p.sandbox = sp

	return p, nil
}

// Implements host.Provisioner.
func (p *sgxProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	// Make sure to return an error early if the SGX runtime loader is not configured.
	if p.cfg.LoaderPath == "" && !p.cfg.InsecureMock {
		return nil, fmt.Errorf("SGX loader binary path is not configured")
	}

	return p.sandbox.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (p *sgxProvisioner) Name() string {
	return "sgx"
}

func (p *sgxProvisioner) loadEnclaveBinaries(comp *bundle.ExplodedComponent) ([]byte, []byte, error) {
	if comp.SGX == nil || comp.SGX.Executable == "" {
		return nil, nil, fmt.Errorf("SGX executable not available in bundle")
	}
	sgxExecutablePath := comp.ExplodedPath(comp.SGX.Executable)

	var (
		sig, sgxs   []byte
		enclaveHash sgx.MrEnclave
		err         error
	)

	if sgxs, err = os.ReadFile(sgxExecutablePath); err != nil {
		return nil, nil, fmt.Errorf("failed to load enclave: %w", err)
	}
	if err = enclaveHash.FromSgxsBytes(sgxs); err != nil {
		return nil, nil, fmt.Errorf("failed to derive EnclaveHash: %w", err)
	}

	if comp.SGX.Signature != "" {
		sgxSignaturePath := comp.ExplodedPath(comp.SGX.Signature)
		sig, err = os.ReadFile(sgxSignaturePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load SIGSTRUCT: %w", err)
		}
	} else if cmdFlags.DebugDontBlameOasis() {
		p.logger.Warn("generating dummy enclave SIGSTRUCT",
			"enclave_hash", enclaveHash,
		)
		if sig, err = sigstruct.UnsafeDebugForEnclave(sgxs); err != nil {
			return nil, nil, fmt.Errorf("failed to generate debug SIGSTRUCT: %w", err)
		}
	} else {
		return nil, nil, fmt.Errorf("enclave SIGSTRUCT not available")
	}

	_, parsed, err := sigstruct.Verify(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate SIGSTRUCT: %w", err)
	}
	if parsed.EnclaveHash != enclaveHash {
		return nil, nil, fmt.Errorf("enclave/SIGSTRUCT mismatch")
	}

	return sgxs, sig, nil
}

func (p *sgxProvisioner) discoverSGXDevice() (string, error) {
	// Different versions of Intel SGX drivers provide different names for
	// the SGX device.  Autodetect which one actually exists.
	sgxDevices := []string{"/dev/sgx_enclave", "/dev/sgx/enclave", "/dev/sgx", "/dev/isgx"}
	for _, dev := range sgxDevices {
		fi, err := os.Stat(dev)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeDevice != 0 {
			return dev, nil
		}
	}

	return "", fmt.Errorf("no SGX device was found on this system")
}

func (p *sgxProvisioner) getSandboxConfig(cfg host.Config, conn sandbox.Connector, runtimeDir string) (process.Config, error) {
	us, ok := conn.(*sandbox.UnixSocketConnector)
	if !ok {
		return process.Config{}, fmt.Errorf("UNIX socket connector is required")
	}

	// To try to avoid bad things from happening if the signature/enclave
	// binaries change out from under us, and because the enclave binary
	// needs to be loaded into memory anyway, this always injects
	// (or copies).
	runtimePath, signaturePath := sandboxMountRuntime, sandboxMountSignature
	if p.cfg.InsecureNoSandbox {
		runtimePath = filepath.Join(runtimeDir, runtimePath)
		signaturePath = filepath.Join(runtimeDir, signaturePath)
	}

	sgxs, sig, err := p.loadEnclaveBinaries(cfg.Component)
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: failed to load enclave/signature: %w", err)
	}

	if p.cfg.InsecureMock {
		// In insecure mock mode, we simply use the non-SGX binary.
		p.logger.Warn("using mock SGX enclaves due to configuration options")

		var pcfg process.Config
		gsc := sandbox.DefaultGetSandboxConfig(p.logger, p.cfg.SandboxBinaryPath)
		pcfg, err = gsc(cfg, conn, runtimeDir)
		if err != nil {
			return process.Config{}, err
		}

		// Add environment variable to configure the mock MRENCLAVE.
		var enclaveHash sgx.MrEnclave
		if err = enclaveHash.FromSgxsBytes(sgxs); err != nil {
			return process.Config{}, err
		}
		if pcfg.Env == nil {
			pcfg.Env = make(map[string]string)
		}
		pcfg.Env["OASIS_MOCK_MRENCLAVE"] = enclaveHash.String()

		return pcfg, nil
	}

	if cfg.Component.SGX == nil {
		return process.Config{}, fmt.Errorf("component '%s' is not an SGX component", cfg.Component.ID())
	}

	sgxDev, err := p.discoverSGXDevice()
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: %w", err)
	}
	p.logger.Info("found SGX device", "path", sgxDev)

	logWrapper := host.NewRuntimeLogWrapper(
		p.logger,
		cfg.Log.Logger(),
		"runtime_id", cfg.ID,
		"runtime_name", cfg.Name,
		"component", cfg.Component.ID(),
		"provisioner", p.Name(),
	)

	args := []string{
		"--host-socket", us.GetGuestSocketPath(),
		"--type", "sgxs",
		"--signature", signaturePath,
		runtimePath,
	}
	if cfg.Component.IsNetworkAllowed() {
		args = append(args, "--allow-network")
	}

	return process.Config{
		Path: p.cfg.LoaderPath,
		Args: args,
		BindRW: map[string]string{
			aesmdSocketPath: "/var/run/aesmd/aesm.socket",
		},
		BindDev: map[string]string{
			sgxDev: sgxDev,
		},
		BindData: map[string]io.Reader{
			runtimePath:   bytes.NewReader(sgxs),
			signaturePath: bytes.NewReader(sig),
		},
		SandboxBinaryPath: p.cfg.SandboxBinaryPath,
		Stdout:            logWrapper,
		Stderr:            logWrapper,
		AllowNetwork:      cfg.Component.IsNetworkAllowed(),
	}, nil
}

func (p *sgxProvisioner) hostInitializer(ctx context.Context, hp *sandbox.HostInitializerParams) (*host.StartedEvent, error) {
	// Initialize TEE.
	var err error
	var ts *teeState
	if ts, err = p.initCapabilityTEE(ctx, hp.Config, hp.Connection); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}
	var capabilityTEE *node.CapabilityTEE
	if capabilityTEE, err = p.updateCapabilityTEE(ctx, ts, hp.Connection); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}

	// Start periodic re-attestation worker.
	updateCapabilityFunc := func(ctx context.Context, hp *sandbox.HostInitializerParams) (*node.CapabilityTEE, error) {
		return p.updateCapabilityTEE(ctx, ts, hp.Connection)
	}
	go sgxCommon.AttestationWorker(p.cfg.RuntimeAttestInterval, p.logger, hp, updateCapabilityFunc)

	return &host.StartedEvent{
		Version:       hp.Version,
		CapabilityTEE: capabilityTEE,
	}, nil
}

func (p *sgxProvisioner) initCapabilityTEE(ctx context.Context, cfg *host.Config, conn protocol.Connection) (*teeState, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	ts := teeState{
		cfg:          cfg,
		insecureMock: p.cfg.InsecureMock,
	}

	targetInfo, err := ts.init(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("error while initializing TEE state: %w", err)
	}
	if err = p.updateTargetInfo(ctx, targetInfo, conn); err != nil {
		return nil, fmt.Errorf("error while updating TEE target info: %w", err)
	}

	return &ts, nil
}

func (p *sgxProvisioner) updateTargetInfo(ctx context.Context, targetInfo []byte, conn protocol.Connection) error {
	_, err := conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakInitRequest: &protocol.RuntimeCapabilityTEERakInitRequest{
				TargetInfo: targetInfo,
			},
		},
	)
	return err
}

func (p *sgxProvisioner) updateCapabilityTEE(ctx context.Context, ts *teeState, conn protocol.Connection) (*node.CapabilityTEE, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	// Update report target info in case the QE identity has changed (e.g. aesmd upgrade).
	targetInfo, err := ts.updateTargetInfo(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("error while updating TEE target info: %w", err)
	}
	if err = p.updateTargetInfo(ctx, targetInfo, conn); err != nil {
		return nil, fmt.Errorf("error while updating TEE target info: %w", err)
	}

	rakQuoteRes, err := conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakReportRequest: &protocol.Empty{},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error while requesting worker quote and public RAK: %w", err)
	}
	rakPub := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.RakPub
	rekPub := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.RekPub
	report := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.Report
	nonce := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.Nonce

	attestation, err := ts.update(ctx, p, conn, report, nonce)
	if err != nil {
		return nil, err
	}

	capabilityTEE := &node.CapabilityTEE{
		Hardware:    node.TEEHardwareIntelSGX,
		RAK:         rakPub,
		REK:         rekPub,
		Attestation: attestation,
	}

	// Endorse TEE capability to support authenticated inter-component EnclaveRPC.
	sgxCommon.EndorseCapabilityTEE(ctx, p.identity, capabilityTEE, conn, p.logger)

	return capabilityTEE, nil
}
