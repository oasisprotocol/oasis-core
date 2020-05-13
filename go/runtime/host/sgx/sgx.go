// Package sgx implements the runtime provisioner for runtimes in Intel SGX enclaves.
package sgx

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx/aesm"
	cmnIAS "github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/common/version"
	ias "github.com/oasislabs/oasis-core/go/ias/api"
	"github.com/oasislabs/oasis-core/go/runtime/host"
	"github.com/oasislabs/oasis-core/go/runtime/host/protocol"
	"github.com/oasislabs/oasis-core/go/runtime/host/sandbox"
	"github.com/oasislabs/oasis-core/go/runtime/host/sandbox/process"
)

const (
	// TODO: Support different locations for the AESMD socket.
	aesmdSocketPath = "/var/run/aesmd/aesm.socket"

	sandboxMountRuntime = "/runtime"

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
	// LoaderPath is the path to the runtime loader binary.
	LoaderPath string

	// IAS is the Intel Attestation Service endpoint.
	IAS ias.Endpoint

	// RuntimeAttestInterval is the interval for periodic runtime re-attestation. If not specified
	// a default will be used.
	RuntimeAttestInterval time.Duration

	// InsecureNoSandbox disables the sandbox and runs the loader directly.
	InsecureNoSandbox bool
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

func (s *sgxProvisioner) getSandboxConfig(rtCfg host.Config, socketPath string, runtimeDir string) process.Config {
	runtimePath := rtCfg.Path
	if !s.cfg.InsecureNoSandbox {
		runtimePath = sandboxMountRuntime
	}

	return process.Config{
		Path: s.cfg.LoaderPath,
		Args: []string{
			"--host-socket", socketPath,
			"--type", "sgxs",
			runtimePath,
		},
		BindRO: map[string]string{
			rtCfg.Path: sandboxMountRuntime,
		},
		BindRW: map[string]string{
			aesmdSocketPath: "/var/run/aesmd/aesm.socket",
		},
		BindDev: map[string]string{
			// TODO: Support different kinds of SGX drivers.
			"/dev/isgx": "/dev/isgx",
		},
	}
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
	if capabilityTEE, err = s.updateCapabilityTEE(ctx, ts, conn); err != nil {
		return nil, fmt.Errorf("failed to initialize TEE: %w", err)
	}

	go s.attestationWorker(ts, p, conn)

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

func (s *sgxProvisioner) updateCapabilityTEE(ctx context.Context, ts *teeState, conn protocol.Connection) (*node.CapabilityTEE, error) {
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

func (s *sgxProvisioner) attestationWorker(ts *teeState, p process.Process, conn protocol.Connection) {
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

			capabilityTEE, err := s.updateCapabilityTEE(context.Background(), ts, conn)
			if err != nil {
				logger.Error("failed to regenerate CapabilityTEE",
					"err", err,
				)
				continue
			}

			// Emit event about the updated CapabilityTEE.
			ts.eventEmitter.EmitEvent(&host.Event{Updated: &host.UpdatedEvent{
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
