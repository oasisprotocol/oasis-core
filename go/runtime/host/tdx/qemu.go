package tdx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
	sgxCommon "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
)

const (
	// defaultQemuSystemPath is the default QEMU system binary path.
	defaultQemuSystemPath = "/usr/bin/qemu-system-x86_64"
	// defaultStartCid is the default start CID.
	defaultStartCid = 0xA5150000
	// defaultRuntimeAttestInterval is the default runtime (re-)attestation interval.
	defaultRuntimeAttestInterval = 2 * time.Hour

	// vsockPortRHP is the VSOCK port used for the Runtime-Host Protocol.
	vsockPortRHP = 1

	runtimeConnectTimeout = 30 * time.Second
)

// QemuConfig is the configuration of the QEMU-based TDX runtime provisioner.
type QemuConfig struct {
	// HostInfo provides information about the host environment.
	HostInfo *protocol.HostInfo

	// CommonStore is a handle to the node's common persistent store.
	CommonStore *persistent.CommonStore

	// PCS is the Intel Provisioning Certification Service quote service.
	PCS pcs.QuoteService
	// Consensus is the consensus layer backend.
	Consensus consensus.Backend
	// Identity is the node identity.
	Identity *identity.Identity

	// RuntimeAttestInterval is the interval for periodic runtime re-attestation. If not specified
	// a default will be used.
	RuntimeAttestInterval time.Duration
}

// QemuExtraConfig is the per-runtime QEMU-specific extra configuration.
type QemuExtraConfig struct {
	// CID is the VSOCK cid to use for this runtime. If zero, the CID is automatically assigned.
	CID uint32
}

type qemuProvisioner struct {
	cfg QemuConfig

	sandbox   host.Provisioner
	pcs       pcs.QuoteService
	consensus consensus.Backend
	identity  *identity.Identity

	l       sync.Mutex
	nextCid uint32

	logger *logging.Logger
}

// Implements host.Provisioner.
func (q *qemuProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	// Assign CID if not explicitly configured.
	if cfg.Extra == nil {
		q.l.Lock()
		cfg.Extra = &QemuExtraConfig{
			CID: q.nextCid,
		}
		q.nextCid++
		q.l.Unlock()
	}

	// Ensure any extra configuration is of the correct type.
	if _, ok := cfg.Extra.(*QemuExtraConfig); !ok {
		return nil, fmt.Errorf("invalid provisioner configuration")
	}

	return q.sandbox.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (q *qemuProvisioner) Name() string {
	return "tdx-qemu"
}

func (q *qemuProvisioner) getSandboxConfig(rtCfg host.Config, _ sandbox.Connector, _ string) (process.Config, error) {
	comp, err := rtCfg.GetComponent()
	if err != nil {
		return process.Config{}, err
	}
	if comp.TEEKind() != component.TEEKindTDX {
		return process.Config{}, fmt.Errorf("component '%s' is not a TDX component", comp.ID())
	}

	cid := rtCfg.Extra.(*QemuExtraConfig).CID // Ensured above.
	bnd := rtCfg.Bundle
	tdxCfg := comp.TDX
	resources := tdxCfg.Resources
	firmware := bnd.ExplodedPath(comp.ID(), tdxCfg.Firmware)

	cfg := process.Config{
		Path: defaultQemuSystemPath,
		Args: []string{
			"-accel", "kvm",
			"-m", fmt.Sprintf("%d", resources.Memory),
			"-smp", fmt.Sprintf("%d", resources.CPUCount),
			"-name", fmt.Sprintf("oasis-%s-%s", bnd.Manifest.ID, comp.ID()),
			"-cpu", "host",
			"-machine", "q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off",
			"-bios", firmware,
			"-nographic",
			"-nodefaults",
			// Serial port.
			"-serial", "stdio",
			"-device", "virtio-serial,max_ports=1",
			// TDX remote attestation via VSOCK.
			"-object", `{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}`,
			// VSOCK.
			"-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", cid),
		},
	}

	// Configure kernel when one is available. We can set up TDs that only include the virtual
	// firmware for special-purpose locked down TDs.
	if tdxCfg.HasKernel() {
		kernelImage := bnd.ExplodedPath(comp.ID(), tdxCfg.Kernel)

		cfg.Args = append(cfg.Args, "-kernel", kernelImage)
		if tdxCfg.HasInitRD() {
			initrdImage := bnd.ExplodedPath(comp.ID(), tdxCfg.InitRD)

			cfg.Args = append(cfg.Args, "-initrd", initrdImage)
		}

		// Configure stage 2 image.
		if tdxCfg.HasStage2() {
			stage2Image := bnd.ExplodedPath(comp.ID(), tdxCfg.Stage2Image)

			cfg.Args = append(cfg.Args,
				// Stage 2 drive.
				"-drive", fmt.Sprintf("format=raw,file=%s,if=none,id=drive0,read-only=on", stage2Image),
				"-device", "virtio-blk-pci,drive=drive0",
			)
		}

		// Append any specified extra kernel options.
		if len(tdxCfg.ExtraKernelOptions) > 0 {
			cfg.Args = append(cfg.Args,
				"-append", strings.Join(tdxCfg.ExtraKernelOptions, " "),
			)
		}
	}

	// Configure network access.
	switch comp.IsNetworkAllowed() {
	case true:
		cfg.Args = append(cfg.Args,
			"-netdev", "user,id=net0",
		)
		cfg.AllowNetwork = true
	case false:
		cfg.Args = append(cfg.Args,
			"-netdev", "user,id=net0,restrict=y",
		)
	}
	cfg.Args = append(cfg.Args,
		"-device", "virtio-net-pci,netdev=net0",
	)

	// Logging.
	logWrapper := host.NewRuntimeLogWrapper(
		q.logger,
		"runtime_id", rtCfg.Bundle.Manifest.ID,
		"runtime_name", rtCfg.Bundle.Manifest.Name,
		"component", comp.ID(),
		"provisioner", q.Name(),
	)
	cfg.Stdout = logWrapper
	cfg.Stderr = logWrapper

	return cfg, nil
}

func (q *qemuProvisioner) updateCapabilityTEE(ctx context.Context, hp *sandbox.HostInitializerParams) (cap *node.CapabilityTEE, aerr error) {
	defer func() {
		sgxCommon.UpdateAttestationMetrics(hp.Runtime.ID(), component.TEEKindTDX, aerr)
	}()

	// Issue the RAK report request which will return the full quote in TDX since the attestation
	// flow is handled transparently via the TDX guest device and VSOCK communication to qgsd
	// running on the host.
	rspRep, err := hp.Connection.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakReportRequest: &protocol.Empty{},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error while requesting worker quote and public RAK: %w", err)
	}
	rakPub := rspRep.RuntimeCapabilityTEERakReportResponse.RakPub
	rekPub := rspRep.RuntimeCapabilityTEERakReportResponse.RekPub
	rawQuote := rspRep.RuntimeCapabilityTEERakReportResponse.Report

	// Prepare the quote policy for local verification. In case a policy is not available or it
	// indicates that TDX is not supported, use the fallback policy so we can provision something.
	fallbackPolicy := &sgxQuote.Policy{
		PCS: &pcs.QuotePolicy{
			TCBValidityPeriod:          30,
			MinTCBEvaluationDataNumber: 17,
			TDX:                        &pcs.TdxQuotePolicy{},
		},
	}
	quotePolicy, err := sgxCommon.GetQuotePolicy(ctx, hp.Config, q.consensus, fallbackPolicy)
	if err != nil {
		return nil, err
	}
	if quotePolicy.PCS == nil {
		quotePolicy.PCS = fallbackPolicy.PCS
	}
	if quotePolicy.PCS.TDX == nil {
		quotePolicy.PCS.TDX = fallbackPolicy.PCS.TDX
	}

	// Resolve the quote and fetch required collateral.
	quoteBundle, err := q.pcs.ResolveQuote(ctx, rawQuote, quotePolicy.PCS)
	if err != nil {
		return nil, fmt.Errorf("error while resolving quote: %w", err)
	}

	attestation, err := sgxCommon.UpdateRuntimeQuote(ctx, hp.Connection, quoteBundle)
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
	sgxCommon.EndorseCapabilityTEE(ctx, q.identity, capabilityTEE, hp.Connection, q.logger)

	return capabilityTEE, nil
}

func (q *qemuProvisioner) hostInitializer(ctx context.Context, hp *sandbox.HostInitializerParams) (*host.StartedEvent, error) {
	capabilityTEE, err := q.updateCapabilityTEE(ctx, hp)
	if err != nil {
		return nil, err
	}

	// Start periodic re-attestation worker.
	go sgxCommon.AttestationWorker(q.cfg.RuntimeAttestInterval, q.logger, hp, q.updateCapabilityTEE)

	return &host.StartedEvent{
		Version:       hp.Version,
		CapabilityTEE: capabilityTEE,
	}, nil
}

// NewQemu creates a new QEMU-based TDX runtime provisioner.
func NewQemu(cfg QemuConfig) (host.Provisioner, error) {
	// Use a default RuntimeAttestInterval if none was provided.
	if cfg.RuntimeAttestInterval == 0 {
		cfg.RuntimeAttestInterval = defaultRuntimeAttestInterval
	}

	sgxCommon.InitMetrics()

	q := &qemuProvisioner{
		cfg:       cfg,
		pcs:       cfg.PCS,
		consensus: cfg.Consensus,
		identity:  cfg.Identity,
		nextCid:   defaultStartCid, // TODO: Could also include the local PID.
		logger:    logging.GetLogger("runtime/host/tdx/qemu"),
	}
	p, err := sandbox.New(sandbox.Config{
		Connector:         newVsockConnector,
		GetSandboxConfig:  q.getSandboxConfig,
		HostInfo:          cfg.HostInfo,
		HostInitializer:   q.hostInitializer,
		InsecureNoSandbox: true, // No sandbox is needed for TDX.
		Logger:            q.logger,
	})
	if err != nil {
		return nil, err
	}
	q.sandbox = p

	return q, nil
}

// vsockConnector is a VSOCK-based connector.
type vsockConnector struct {
	cid uint32
}

func newVsockConnector(_ *logging.Logger, _ string, _ bool) (sandbox.Connector, error) {
	return &vsockConnector{}, nil
}

// Implements sandbox.Connector.
func (vs *vsockConnector) Configure(rtCfg *host.Config, _ *process.Config) error {
	vs.cid = rtCfg.Extra.(*QemuExtraConfig).CID // Ensured above.
	return nil
}

// Implements sandbox.Connector.
func (vs *vsockConnector) Connect(p process.Process) (net.Conn, error) {
	if vs.cid == 0 {
		return nil, fmt.Errorf("CID not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), runtimeConnectTimeout)
	defer cancel()

	for {
		conn, err := vsock.Dial(vs.cid, vsockPortRHP, nil)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("failed to connect to the runtime VM: %w", err)
			case <-p.Wait():
				return nil, fmt.Errorf("runtime has terminated before a connection was established: %w", err)
			case <-time.After(time.Second):
				continue
			}
		}

		return conn, nil
	}
}

// Implements sandbox.Connector.
func (vs *vsockConnector) Close() {
	vs.cid = 0
}
