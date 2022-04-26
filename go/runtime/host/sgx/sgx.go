// Package sgx implements the runtime provisioner for runtimes in Intel SGX enclaves.
package sgx

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/aesm"
	cmnIAS "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/sigstruct"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
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

	// Runtime RAK initialization timeout.
	//
	// This can take a long time in deployments that run multiple
	// nodes on a single machine, all sharing the same EPC.
	runtimeRAKTimeout = 60 * time.Second
	// Runtime attest interval.
	defaultRuntimeAttestInterval = 1 * time.Hour
)

// Config contains SGX-specific provisioner configuration options.
type Config struct {
	// HostInfo provides information about the host environment.
	HostInfo *protocol.HostInfo

	// LoaderPath is the path to the runtime loader binary.
	LoaderPath string

	// IAS is the Intel Attestation Service endpoint.
	IAS ias.Endpoint

	// RuntimeAttestInterval is the interval for periodic runtime re-attestation. If not specified
	// a default will be used.
	RuntimeAttestInterval time.Duration

	// SandboxBinaryPath is the path to the sandbox support binary.
	SandboxBinaryPath string

	// InsecureNoSandbox disables the sandbox and runs the loader directly.
	InsecureNoSandbox bool
}

// RuntimeExtra is the extra configuration for SGX runtimes.
type RuntimeExtra struct {
	// SignaturePath is the path to the runtime (enclave) SIGSTRUCT.
	SignaturePath string

	// UnsafeDebugGenerateSigstruct allows the generation of a dummy SIGSTRUCT
	// if an actual signature is unavailable.
	UnsafeDebugGenerateSigstruct bool
}

type teeState struct {
	runtimeID    common.Namespace
	eventEmitter host.RuntimeEventEmitter

	epidGID   uint32
	spid      cmnIAS.SPID
	quoteType *cmnIAS.SignatureType
}

type sgxProvisioner struct {
	sync.Mutex

	cfg Config

	sandbox host.Provisioner
	ias     ias.Endpoint
	aesm    *aesm.Client

	logger *logging.Logger
}

func (s *sgxProvisioner) loadEnclaveBinaries(rtCfg host.Config) ([]byte, []byte, error) {
	var (
		sig, sgxs   []byte
		enclaveHash sgx.MrEnclave
		err         error
	)

	if sgxs, err = ioutil.ReadFile(rtCfg.Bundle.Path); err != nil {
		return nil, nil, fmt.Errorf("failed to load enclave: %w", err)
	}
	if err = enclaveHash.FromSgxsBytes(sgxs); err != nil {
		return nil, nil, fmt.Errorf("failed to derive EnclaveHash: %w", err)
	}

	// If the path to an existing SIGSTRUCT is provided, load it.
	rtExtra, ok := rtCfg.Extra.(*RuntimeExtra)
	if !ok {
		return nil, nil, fmt.Errorf("sgx enclave configuration not available")
	}

	if rtExtra.SignaturePath != "" {
		sig, err = ioutil.ReadFile(rtExtra.SignaturePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load SIGSTRUCT: %w", err)
		}
	} else if rtExtra.UnsafeDebugGenerateSigstruct && cmdFlags.DebugDontBlameOasis() {
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
	sgxDevices := []string{"/dev/sgx", "/dev/sgx/enclave", "/dev/sgx_enclave", "/dev/isgx"}
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
	// To try to avoid bad things from happening if the signature/enclave
	// binaries change out from under us, and because the enclave binary
	// needs to be loaded into memory anyway, this always injects
	// (or copies).
	runtimePath, signaturePath := sandboxMountRuntime, sandboxMountSignature
	if s.cfg.InsecureNoSandbox {
		runtimePath = filepath.Join(runtimeDir, runtimePath)
		signaturePath = filepath.Join(runtimeDir, signaturePath)
	}

	sgxs, sig, err := s.loadEnclaveBinaries(rtCfg)
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: failed to load enclave/signature: %w", err)
	}

	sgxDev, err := s.discoverSGXDevice()
	if err != nil {
		return process.Config{}, fmt.Errorf("host/sgx: %w", err)
	}
	s.logger.Info("found SGX device", "path", sgxDev)

	logWrapper := host.NewRuntimeLogWrapper(
		s.logger,
		"runtime_id", rtCfg.Bundle.Manifest.ID.Hex(),
		"runtime_name", rtCfg.Bundle.Manifest.Name)

	return process.Config{
		Path: s.cfg.LoaderPath,
		Args: []string{
			"--host-socket", socketPath,
			"--type", "sgxs",
			"--signature", signaturePath,
			runtimePath,
		},
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
	}, nil
}

func (s *sgxProvisioner) hostInitializer(
	ctx context.Context,
	rt host.Runtime,
	version version.Version,
	p process.Process,
	conn protocol.Connection,
) (*host.StartedEvent, error) {
	// Initialize TEE.
	var err error
	var ts *teeState
	if ts, err = s.initCapabilityTEE(ctx, rt, conn); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}
	var capabilityTEE *node.CapabilityTEE
	if capabilityTEE, err = s.updateCapabilityTEE(ctx, s.logger, ts, conn); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}

	go s.attestationWorker(ts, p, conn, version)

	return &host.StartedEvent{
		Version:       version,
		CapabilityTEE: capabilityTEE,
	}, nil
}

func (s *sgxProvisioner) initCapabilityTEE(ctx context.Context, rt host.Runtime, conn protocol.Connection) (*teeState, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	ts := teeState{
		runtimeID: rt.ID(),
		// We know that the runtime implementation provided by sandbox runtime provisioner
		// implements the RuntimeEventEmitter interface.
		eventEmitter: rt.(host.RuntimeEventEmitter),
	}

	qi, err := s.aesm.InitQuote(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote info from AESMD: %w", err)
	}
	ts.epidGID = binary.LittleEndian.Uint32(qi.GID[:])

	spidInfo, err := s.ias.GetSPIDInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error while getting IAS SPID information: %w", err)
	}
	ts.spid = spidInfo.SPID
	ts.quoteType = &spidInfo.QuoteSignatureType

	if _, err = conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakInitRequest: &protocol.RuntimeCapabilityTEERakInitRequest{
				TargetInfo: qi.TargetInfo,
			},
		},
	); err != nil {
		return nil, fmt.Errorf("error while initializing RAK: %w", err)
	}

	return &ts, nil
}

func (s *sgxProvisioner) updateCapabilityTEE(ctx context.Context, logger *logging.Logger, ts *teeState, conn protocol.Connection) (*node.CapabilityTEE, error) {
	ctx, cancel := context.WithTimeout(ctx, runtimeRAKTimeout)
	defer cancel()

	// Update the SigRL (Not cached, knowing if revoked is important).
	sigRL, err := s.ias.GetSigRL(ctx, ts.epidGID)
	if err != nil {
		return nil, fmt.Errorf("error while requesting SigRL: %w", err)
	}
	sigRL = cbor.FixSliceForSerde(sigRL)

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
	report := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.Report
	nonce := rakQuoteRes.RuntimeCapabilityTEERakReportResponse.Nonce

	quote, err := s.aesm.GetQuote(
		ctx,
		report,
		*ts.quoteType,
		ts.spid,
		make([]byte, 16),
		sigRL,
	)
	if err != nil {
		return nil, fmt.Errorf("error while getting quote: %w", err)
	}

	evidence := ias.Evidence{
		RuntimeID: ts.runtimeID,
		Quote:     quote,
		Nonce:     nonce,
	}

	avrBundle, err := s.ias.VerifyEvidence(ctx, &evidence)
	if err != nil {
		return nil, fmt.Errorf("error while verifying attestation evidence: %w", err)
	}

	avrBundle.Body = cbor.FixSliceForSerde(avrBundle.Body)
	avrBundle.CertificateChain = cbor.FixSliceForSerde(avrBundle.CertificateChain)
	avrBundle.Signature = cbor.FixSliceForSerde(avrBundle.Signature)

	_, err = conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakAvrRequest: &protocol.RuntimeCapabilityTEERakAvrRequest{
				AVR: *avrBundle,
			},
		},
	)
	if err != nil {
		// If we are here, presumably the AVR is well-formed (VerifyEvidence
		// succeeded).  Since this is more than likely the AVR indicating
		// rejection, deserialize it and log some pertinent details.
		avr, decErr := cmnIAS.UnsafeDecodeAVR(avrBundle.Body)
		if decErr == nil {
			switch avr.ISVEnclaveQuoteStatus {
			case cmnIAS.QuoteOK, cmnIAS.QuoteSwHardeningNeeded:
				// That's odd, the quote checks out as ok.  Can't
				// really get further information.
			default:
				// This probably has to do with the never-ending series of
				// speculative execution trashfires, so log the vulns and
				// quote status.
				logger.Error("attestation likely rejected by IAS",
					"quote_status", avr.ISVEnclaveQuoteStatus.String(),
					"advisory_ids", avr.AdvisoryIDs,
				)
			}
		}

		return nil, fmt.Errorf("error while configuring AVR: %w", err)
	}

	attestation := cbor.Marshal(avrBundle)
	capabilityTEE := &node.CapabilityTEE{
		Hardware:    node.TEEHardwareIntelSGX,
		RAK:         rakPub,
		Attestation: attestation,
	}

	return capabilityTEE, nil
}

func (s *sgxProvisioner) attestationWorker(ts *teeState, p process.Process, conn protocol.Connection, version version.Version) {
	t := time.NewTicker(s.cfg.RuntimeAttestInterval)
	defer t.Stop()

	logger := s.logger.With("runtime_id", ts.runtimeID)

	for {
		select {
		case <-p.Wait():
			// Process has terminated.
			return
		case <-t.C:
			// Update CapabilityTEE.
			logger.Info("regenerating CapabilityTEE")

			capabilityTEE, err := s.updateCapabilityTEE(context.Background(), logger, ts, conn)
			if err != nil {
				logger.Error("failed to regenerate CapabilityTEE",
					"err", err,
				)
				continue
			}

			// Emit event about the updated CapabilityTEE.
			ts.eventEmitter.EmitEvent(&host.Event{Updated: &host.UpdatedEvent{
				Version:       version,
				CapabilityTEE: capabilityTEE,
			}})
		}
	}
}

// Implements host.Provisioner.
func (s *sgxProvisioner) NewRuntime(ctx context.Context, cfg host.Config) (host.Runtime, error) {
	return s.sandbox.NewRuntime(ctx, cfg)
}

// New creates a new Intel SGX runtime provisioner.
func New(cfg Config) (host.Provisioner, error) {
	// Use a default RuntimeAttestInterval if none was provided.
	if cfg.RuntimeAttestInterval == 0 {
		cfg.RuntimeAttestInterval = defaultRuntimeAttestInterval
	}

	s := &sgxProvisioner{
		cfg:    cfg,
		ias:    cfg.IAS,
		aesm:   aesm.NewClient(aesmdSocketPath),
		logger: logging.GetLogger("runtime/host/sgx"),
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
