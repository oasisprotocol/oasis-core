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

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/sigstruct"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
)

const (
	// TODO: Support different locations for the AESMD socket.
	aesmdSocketPath = "/var/run/aesmd/aesm.socket"

	sandboxMountRuntime   = "/runtime"
	sandboxMountSignature = "/runtime.sig"

	// The service name for the common store to use for SGX-related persistent data.
	serviceStoreName = "runtime_host_sgx"

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
	// PCS is the Intel Provisioning Certification Service client.
	PCS pcs.Client
	// Consensus is the consensus layer backend.
	Consensus consensus.Backend
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

type teeStateImpl interface {
	// Init initializes the TEE state and returns the QE target info.
	Init(ctx context.Context, sp *sgxProvisioner, runtimeID common.Namespace, version version.Version) ([]byte, error)

	// Update updates the TEE state and returns a new attestation.
	Update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error)
}

type teeState struct {
	runtimeID    common.Namespace
	version      version.Version
	eventEmitter host.RuntimeEventEmitter

	insecureMock bool

	impl teeStateImpl
}

func (ts *teeState) init(ctx context.Context, sp *sgxProvisioner) ([]byte, error) {
	if ts.impl != nil {
		return nil, fmt.Errorf("already initialized")
	}

	var (
		targetInfo []byte
		err        error
	)

	// When insecure mock SGX is enabled, use mock implementation.
	if ts.insecureMock {
		ts.impl = &teeStateMock{}
		return ts.impl.Init(ctx, sp, ts.runtimeID, ts.version)
	}

	// Try ECDSA first. If it fails, try EPID.
	implECDSA := &teeStateECDSA{}
	if targetInfo, err = implECDSA.Init(ctx, sp, ts.runtimeID, ts.version); err != nil {
		sp.logger.Debug("ECDSA attestation initialization failed, trying EPID",
			"err", err,
		)

		implEPID := &teeStateEPID{}
		if targetInfo, err = implEPID.Init(ctx, sp, ts.runtimeID, ts.version); err != nil {
			return nil, err
		}
		ts.impl = implEPID
	} else {
		ts.impl = implECDSA
	}

	return targetInfo, nil
}

func (ts *teeState) updateTargetInfo(ctx context.Context, sp *sgxProvisioner) ([]byte, error) {
	if ts.impl == nil {
		return nil, fmt.Errorf("not initialized")
	}
	return ts.impl.Init(ctx, sp, ts.runtimeID, ts.version)
}

func (ts *teeState) update(ctx context.Context, sp *sgxProvisioner, conn protocol.Connection, report []byte, nonce string) ([]byte, error) {
	if ts.impl == nil {
		return nil, fmt.Errorf("not initialized")
	}

	attestation, err := ts.impl.Update(ctx, sp, conn, report, nonce)

	updateAttestationMetrics(ts.runtimeID.String(), err)

	return attestation, err
}

type sgxProvisioner struct {
	sync.Mutex

	cfg Config

	sandbox   host.Provisioner
	ias       []ias.Endpoint
	pcs       pcs.Client
	aesm      *aesm.Client
	consensus consensus.Backend
	identity  *identity.Identity

	logger       *logging.Logger
	serviceStore *persistent.ServiceStore
}

func (s *sgxProvisioner) loadEnclaveBinaries(rtCfg host.Config, comp *bundle.Component) ([]byte, []byte, error) {
	if comp.SGX.Executable == "" {
		return nil, nil, fmt.Errorf("SGX executable not available in bundle")
	}
	sgxExecutablePath := rtCfg.Bundle.ExplodedPath(rtCfg.Bundle.ExplodedDataDir, comp.SGX.Executable)

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
		sgxSignaturePath := rtCfg.Bundle.ExplodedPath(rtCfg.Bundle.ExplodedDataDir, comp.SGX.Signature)
		sig, err = os.ReadFile(sgxSignaturePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load SIGSTRUCT: %w", err)
		}
	} else if cmdFlags.DebugDontBlameOasis() {
		s.logger.Warn("generating dummy enclave SIGSTRUCT",
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

func (s *sgxProvisioner) discoverSGXDevice() (string, error) {
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

func (s *sgxProvisioner) getSandboxConfig(rtCfg host.Config, socketPath, runtimeDir string) (process.Config, error) {
	if numComps := len(rtCfg.Components); numComps != 1 {
		return process.Config{}, fmt.Errorf("expected a single component (got %d)", numComps)
	}
	comp := rtCfg.Bundle.Manifest.GetComponentByID(rtCfg.Components[0])
	if comp == nil {
		return process.Config{}, fmt.Errorf("component '%s' not available", rtCfg.Components[0])
	}

	// To try to avoid bad things from happening if the signature/enclave
	// binaries change out from under us, and because the enclave binary
	// needs to be loaded into memory anyway, this always injects
	// (or copies).
	runtimePath, signaturePath := sandboxMountRuntime, sandboxMountSignature
	if s.cfg.InsecureNoSandbox {
		runtimePath = filepath.Join(runtimeDir, runtimePath)
		signaturePath = filepath.Join(runtimeDir, signaturePath)
	}

	sgxs, sig, err := s.loadEnclaveBinaries(rtCfg, comp)
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: failed to load enclave/signature: %w", err)
	}

	if s.cfg.InsecureMock {
		// In insecure mock mode, we simply use the non-SGX binary.
		s.logger.Warn("using mock SGX enclaves due to configuration options")

		var cfg process.Config
		gsc := sandbox.DefaultGetSandboxConfig(s.logger, s.cfg.SandboxBinaryPath)
		cfg, err = gsc(rtCfg, socketPath, runtimeDir)
		if err != nil {
			return process.Config{}, err
		}

		// Add environment variable to configure the mock MRENCLAVE.
		var enclaveHash sgx.MrEnclave
		if err = enclaveHash.FromSgxsBytes(sgxs); err != nil {
			return process.Config{}, err
		}
		cfg.Env["OASIS_MOCK_MRENCLAVE"] = enclaveHash.String()

		return cfg, nil
	}

	sgxDev, err := s.discoverSGXDevice()
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: %w", err)
	}
	s.logger.Info("found SGX device", "path", sgxDev)

	logWrapper := host.NewRuntimeLogWrapper(
		s.logger,
		"runtime_id", rtCfg.Bundle.Manifest.ID,
		"runtime_name", rtCfg.Bundle.Manifest.Name,
		"component", comp.Kind,
	)

	args := []string{
		"--host-socket", socketPath,
		"--type", "sgxs",
		"--signature", signaturePath,
		runtimePath,
	}
	if comp.IsNetworkAllowed() {
		args = append(args, "--allow-network")
	}

	return process.Config{
		Path: s.cfg.LoaderPath,
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
		SandboxBinaryPath: s.cfg.SandboxBinaryPath,
		Stdout:            logWrapper,
		Stderr:            logWrapper,
		AllowNetwork:      comp.IsNetworkAllowed(),
	}, nil
}

func (s *sgxProvisioner) hostInitializer(ctx context.Context, hp *sandbox.HostInitializerParams) (*host.StartedEvent, error) {
	// Initialize TEE.
	var err error
	var ts *teeState
	if ts, err = s.initCapabilityTEE(ctx, hp.Runtime, hp.Connection, hp.Version); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}
	var capabilityTEE *node.CapabilityTEE
	if capabilityTEE, err = s.updateCapabilityTEE(ctx, ts, hp.Connection); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}

	go s.attestationWorker(ts, hp)

	return &host.StartedEvent{
		Version:       hp.Version,
		CapabilityTEE: capabilityTEE,
	}, nil
}

func (s *sgxProvisioner) initCapabilityTEE(ctx context.Context, rt host.Runtime, conn protocol.Connection, version version.Version) (*teeState, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	ts := teeState{
		runtimeID: rt.ID(),
		version:   version,
		// We know that the runtime implementation provided by sandbox runtime provisioner
		// implements the RuntimeEventEmitter interface.
		eventEmitter: rt.(host.RuntimeEventEmitter),
		insecureMock: s.cfg.InsecureMock,
	}

	targetInfo, err := ts.init(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("error while initializing TEE state: %w", err)
	}
	if err = s.updateTargetInfo(ctx, targetInfo, conn); err != nil {
		return nil, fmt.Errorf("error while updating TEE target info: %w", err)
	}

	return &ts, nil
}

func (s *sgxProvisioner) updateTargetInfo(ctx context.Context, targetInfo []byte, conn protocol.Connection) error {
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

func (s *sgxProvisioner) updateCapabilityTEE(ctx context.Context, ts *teeState, conn protocol.Connection) (*node.CapabilityTEE, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	// Update report target info in case the QE identity has changed (e.g. aesmd upgrade).
	targetInfo, err := ts.updateTargetInfo(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("error while updating TEE target info: %w", err)
	}
	if err = s.updateTargetInfo(ctx, targetInfo, conn); err != nil {
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

	attestation, err := ts.update(ctx, s, conn, report, nonce)
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
	s.endorseCapabilityTEE(ctx, capabilityTEE, conn)

	return capabilityTEE, nil
}

func (s *sgxProvisioner) endorseCapabilityTEE(ctx context.Context, capabilityTEE *node.CapabilityTEE, conn protocol.Connection) {
	ri, err := conn.GetInfo()
	if err != nil {
		s.logger.Error("failed to get host information, not endorsing local component",
			"err", err,
		)
		return
	}
	if !ri.Features.EndorsedCapabilityTEE {
		s.logger.Debug("runtime does not support endorsed TEE capabilities, skipping endorsement")
		return
	}

	// Endorse CapabilityTEE by signing it under the proper domain separation context.
	nodeSignature, err := signature.Sign(
		s.identity.NodeSigner,
		node.EndorseCapabilityTEESignatureContext,
		cbor.Marshal(capabilityTEE),
	)
	if err != nil {
		s.logger.Error("failed to sign endorsement of local component",
			"err", err,
		)
		return
	}

	_, err = conn.Call(ctx, &protocol.Body{
		RuntimeCapabilityTEEUpdateEndorsementRequest: &protocol.RuntimeCapabilityTEEUpdateEndorsementRequest{
			EndorsedCapabilityTEE: node.EndorsedCapabilityTEE{
				CapabilityTEE:   *capabilityTEE,
				NodeEndorsement: *nodeSignature,
			},
		},
	})
	if err != nil {
		s.logger.Error("failed to update endorsement of local component",
			"err", err,
		)
		return
	}

	s.logger.Debug("successfully updated component's TEE capability endorsement")
}

func (s *sgxProvisioner) attestationWorker(ts *teeState, hp *sandbox.HostInitializerParams) {
	t := time.NewTicker(s.cfg.RuntimeAttestInterval)
	defer t.Stop()

	logger := s.logger.With("runtime_id", ts.runtimeID)

	for {
		select {
		case <-hp.Process.Wait():
			// Process has terminated.
			return
		case <-t.C:
			// Re-attest based on the configured interval.
		case <-hp.NotifyUpdateCapabilityTEE:
			// Re-attest when explicitly requested. Also reset the periodic ticker to make sure we
			// don't needlessly re-attest too often.
			t.Reset(s.cfg.RuntimeAttestInterval)
		}

		// Update CapabilityTEE.
		logger.Info("regenerating CapabilityTEE")

		capabilityTEE, err := s.updateCapabilityTEE(context.Background(), ts, hp.Connection)
		if err != nil {
			logger.Error("failed to regenerate CapabilityTEE",
				"err", err,
			)
			continue
		}

		// Emit event about the updated CapabilityTEE.
		ts.eventEmitter.EmitEvent(&host.Event{Updated: &host.UpdatedEvent{
			Version:       hp.Version,
			CapabilityTEE: capabilityTEE,
		}})
	}
}

// Implements host.Provisioner.
func (s *sgxProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	// Make sure to return an error early if the SGX runtime loader is not configured.
	if s.cfg.LoaderPath == "" && !s.cfg.InsecureMock {
		return nil, fmt.Errorf("SGX loader binary path is not configured")
	}

	return s.sandbox.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (s *sgxProvisioner) Name() string {
	return "sgx"
}

// New creates a new Intel SGX runtime provisioner.
func New(cfg Config) (host.Provisioner, error) {
	// Use a default RuntimeAttestInterval if none was provided.
	if cfg.RuntimeAttestInterval == 0 {
		cfg.RuntimeAttestInterval = defaultRuntimeAttestInterval
	}

	initMetrics()

	s := &sgxProvisioner{
		cfg:          cfg,
		ias:          cfg.IAS,
		pcs:          cfg.PCS,
		aesm:         aesm.NewClient(aesmdSocketPath),
		consensus:    cfg.Consensus,
		identity:     cfg.Identity,
		logger:       logging.GetLogger("runtime/host/sgx"),
		serviceStore: cfg.CommonStore.GetServiceStore(serviceStoreName),
	}
	p, err := sandbox.New(sandbox.Config{
		GetSandboxConfig:  s.getSandboxConfig,
		HostInfo:          cfg.HostInfo,
		HostInitializer:   s.hostInitializer,
		InsecureNoSandbox: cfg.InsecureNoSandbox,
		Logger:            s.logger,
	})
	if err != nil {
		return nil, err
	}
	s.sandbox = p

	return s, nil
}
