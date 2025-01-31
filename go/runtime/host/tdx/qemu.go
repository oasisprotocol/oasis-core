package tdx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
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
	// defaultQemuImgPath is the default qemu-bin binary path.
	defaultQemuImgPath = "/usr/bin/qemu-img"
	// defaultStartCid is the default start CID.
	defaultStartCid = 0xA5150000
	// defaultRuntimeAttestInterval is the default runtime (re-)attestation interval.
	defaultRuntimeAttestInterval = 2 * time.Hour
	// persistentImageDir is the name of the directory within the runtime data directory
	// where persistent overlay images can be stored.
	persistentImageDir = "images"

	// vsockPortRHP is the VSOCK port used for the Runtime-Host Protocol.
	vsockPortRHP = 1

	runtimeConnectTimeout = 30 * time.Second
)

// QemuConfig is the configuration of the QEMU-based TDX runtime provisioner.
type QemuConfig struct {
	// DataDir is the runtime data directory.
	DataDir string
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

// NewQemuProvisioner creates a new QEMU-based TDX runtime provisioner.
func NewQemuProvisioner(cfg QemuConfig) (host.Provisioner, error) {
	// Use a default RuntimeAttestInterval if none was provided.
	if cfg.RuntimeAttestInterval == 0 {
		cfg.RuntimeAttestInterval = defaultRuntimeAttestInterval
	}

	sgxCommon.InitMetrics()

	p := &qemuProvisioner{
		cfg:       cfg,
		pcs:       cfg.PCS,
		consensus: cfg.Consensus,
		identity:  cfg.Identity,
		nextCid:   defaultStartCid, // TODO: Could also include the local PID.
		logger:    logging.GetLogger("runtime/host/tdx/qemu"),
	}
	sp, err := sandbox.NewProvisioner(sandbox.Config{
		Connector:         newVsockConnector,
		GetSandboxConfig:  p.getSandboxConfig,
		HostInfo:          cfg.HostInfo,
		HostInitializer:   p.hostInitializer,
		InsecureNoSandbox: true, // No sandbox is needed for TDX.
		Logger:            p.logger,
	})
	if err != nil {
		return nil, err
	}
	p.sandbox = sp

	return p, nil
}

// Implements host.Provisioner.
func (p *qemuProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	// Assign CID if not explicitly configured.
	if cfg.Extra == nil {
		p.l.Lock()
		cfg.Extra = &QemuExtraConfig{
			CID: p.nextCid,
		}
		p.nextCid++
		p.l.Unlock()
	}

	// Ensure any extra configuration is of the correct type.
	if _, ok := cfg.Extra.(*QemuExtraConfig); !ok {
		return nil, fmt.Errorf("invalid provisioner configuration")
	}

	return p.sandbox.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (p *qemuProvisioner) Name() string {
	return "tdx-qemu"
}

func (p *qemuProvisioner) getSandboxConfig(cfg host.Config, _ sandbox.Connector, _ string) (process.Config, error) {
	if cfg.Component.TDX == nil {
		return process.Config{}, fmt.Errorf("component '%s' is not a TDX component", cfg.Component.ID())
	}

	cid := cfg.Extra.(*QemuExtraConfig).CID // Ensured above.
	tdxCfg := cfg.Component.TDX
	resources := tdxCfg.Resources
	firmware := cfg.Component.ExplodedPath(tdxCfg.Firmware)

	pcfg := process.Config{
		Path: defaultQemuSystemPath,
		Args: []string{
			"-accel", "kvm",
			"-m", fmt.Sprintf("%d", resources.Memory),
			"-smp", fmt.Sprintf("%d", resources.CPUCount),
			"-name", fmt.Sprintf("oasis-%s-%s", cfg.ID, cfg.Component.ID()),
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
		kernelImage := cfg.Component.ExplodedPath(tdxCfg.Kernel)

		pcfg.Args = append(pcfg.Args, "-kernel", kernelImage)
		if tdxCfg.HasInitRD() {
			initrdImage := cfg.Component.ExplodedPath(tdxCfg.InitRD)

			pcfg.Args = append(pcfg.Args, "-initrd", initrdImage)
		}

		// Configure stage 2 image.
		if tdxCfg.HasStage2() {
			stage2Image := cfg.Component.ExplodedPath(tdxCfg.Stage2Image)
			stage2Format := tdxCfg.Stage2Format
			switch stage2Format {
			case "":
				// Default to raw format.
				stage2Format = "raw"
			case "raw", "qcow2":
				// These formats are supported as-is.
			default:
				return process.Config{}, fmt.Errorf("format '%s' is not supported", stage2Format)
			}

			// Set up a persistent overlay image when configured to do so.
			snapshotMode := "on" // Default to ephemeral images.
			if tdxCfg.Stage2Persist {
				var err error
				stage2Image, err = p.createPersistentOverlayImage(cfg, cfg.Component, stage2Image, stage2Format)
				if err != nil {
					return process.Config{}, err
				}
				stage2Format = "qcow2"
				snapshotMode = "off"
			}

			pcfg.Args = append(pcfg.Args,
				// Stage 2 drive.
				"-drive", fmt.Sprintf("format=%s,file=%s,if=none,id=drive0,snapshot=%s", stage2Format, stage2Image, snapshotMode),
				"-device", "virtio-blk-pci,drive=drive0",
			)
		}

		// Append any specified extra kernel options.
		if len(tdxCfg.ExtraKernelOptions) > 0 {
			pcfg.Args = append(pcfg.Args,
				"-append", strings.Join(tdxCfg.ExtraKernelOptions, " "),
			)
		}
	}

	// Configure network access.
	switch cfg.Component.IsNetworkAllowed() {
	case true:
		pcfg.Args = append(pcfg.Args,
			"-netdev", "user,id=net0",
		)
		pcfg.AllowNetwork = true
	case false:
		pcfg.Args = append(pcfg.Args,
			"-netdev", "user,id=net0,restrict=y",
		)
	}
	pcfg.Args = append(pcfg.Args,
		"-device", "virtio-net-pci,netdev=net0",
	)

	// Logging.
	logWrapper := host.NewRuntimeLogWrapper(
		p.logger,
		"runtime_id", cfg.ID,
		"runtime_name", cfg.Name,
		"component", cfg.Component.ID(),
		"provisioner", p.Name(),
	)
	pcfg.Stdout = logWrapper
	pcfg.Stderr = logWrapper

	return pcfg, nil
}

// createPersistentOverlayImage creates a persistent overlay image for the given backing image and
// returns the full path to the overlay image. In case the image already exists, it is reused.
//
// The format of the resulting image is always qcow2.
func (p *qemuProvisioner) createPersistentOverlayImage(
	rtCfg host.Config,
	comp *bundle.ExplodedComponent,
	image string,
	format string,
) (string, error) {
	compID, _ := comp.ID().MarshalText()
	imageDir := filepath.Join(p.cfg.DataDir, persistentImageDir, rtCfg.ID.String(), string(compID))
	imageFn := filepath.Join(imageDir, fmt.Sprintf("%s.overlay", filepath.Base(image)))
	switch _, err := os.Stat(imageFn); {
	case err == nil:
		// Image already exists, perform a rebase operation to account for the backing file location
		// changing (e.g. due to an upgrade).
		cmd := exec.Command(
			defaultQemuImgPath,
			"rebase",
			"-u",
			"-f", "qcow2",
			"-b", image,
			"-F", format,
			imageFn,
		)
		var out strings.Builder
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to rebase persistent overlay image: %s\n%w", out.String(), err)
		}
	case errors.Is(err, os.ErrNotExist):
		// Create image directory if it doesn't yet exist.
		if err := common.Mkdir(imageDir); err != nil {
			return "", fmt.Errorf("failed to create persistent overlay image directory: %w", err)
		}

		// Create the persistent overlay image.
		cmd := exec.Command(
			defaultQemuImgPath,
			"create",
			"-f", "qcow2",
			"-b", image,
			"-F", format,
			imageFn,
		)
		var out strings.Builder
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to create persistent overlay image: %s\n%w", out.String(), err)
		}
	default:
		return "", fmt.Errorf("failed to stat persistent overlay image: %w", err)
	}
	return imageFn, nil
}

func (p *qemuProvisioner) updateCapabilityTEE(ctx context.Context, hp *sandbox.HostInitializerParams) (capTEE *node.CapabilityTEE, aerr error) {
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
	quotePolicy, err := sgxCommon.GetQuotePolicy(ctx, hp.Config, p.consensus, fallbackPolicy)
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
	quoteBundle, err := p.pcs.ResolveQuote(ctx, rawQuote, quotePolicy.PCS)
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
	sgxCommon.EndorseCapabilityTEE(ctx, p.identity, capabilityTEE, hp.Connection, p.logger)

	return capabilityTEE, nil
}

func (p *qemuProvisioner) hostInitializer(ctx context.Context, hp *sandbox.HostInitializerParams) (*host.StartedEvent, error) {
	capabilityTEE, err := p.updateCapabilityTEE(ctx, hp)
	if err != nil {
		return nil, err
	}

	// Start periodic re-attestation worker.
	go sgxCommon.AttestationWorker(p.cfg.RuntimeAttestInterval, p.logger, hp, p.updateCapabilityTEE)

	return &host.StartedEvent{
		Version:       hp.Version,
		CapabilityTEE: capabilityTEE,
	}, nil
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
