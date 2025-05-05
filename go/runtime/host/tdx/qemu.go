package tdx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
	sgxCommon "github.com/oasisprotocol/oasis-core/go/runtime/host/sgx/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/volume"
)

const (
	// defaultQemuSystemPath is the default QEMU system binary path.
	defaultQemuSystemPath = "/usr/bin/qemu-system-x86_64"
	// defaultQemuImgPath is the default qemu-bin binary path.
	defaultQemuImgPath = "/usr/bin/qemu-img"
	// defaultRuntimeAttestInterval is the default runtime (re-)attestation interval.
	defaultRuntimeAttestInterval = 2 * time.Hour

	// vsockPortRHP is the VSOCK port used for the Runtime-Host Protocol.
	vsockPortRHP = 1

	runtimeConnectTimeout = 30 * time.Second
)

// QemuConfig is the configuration of the QEMU-based TDX runtime provisioner.
type QemuConfig struct {
	// DataDir is the node data directory.
	DataDir string
	// HostInfo provides information about the host environment.
	HostInfo *protocol.HostInfo

	// CommonStore is a handle to the node's common persistent store.
	CommonStore *persistent.CommonStore

	// PCS is the Intel Provisioning Certification Service quote service.
	PCS pcs.QuoteService
	// Consensus is the consensus layer backend.
	Consensus consensus.Service
	// Identity is the node identity.
	Identity *identity.Identity

	// CidPool is a pool of CIDs to allocate from.
	CidPool *CidPool

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
	consensus consensus.Service
	identity  *identity.Identity
	cidPool   *CidPool

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
		cidPool:   cfg.CidPool,
		logger:    logging.GetLogger("runtime/host/tdx/qemu"),
	}
	sp, err := sandbox.NewProvisioner(sandbox.Config{
		Connector:         newVsockConnector,
		GetSandboxConfig:  p.getSandboxConfig,
		Cleanup:           p.cleanup,
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
	switch extraCfg := cfg.Extra.(type) {
	case nil:
		// Assign CID if not explicitly configured.
		cid, err := p.cidPool.Allocate()
		if err != nil {
			return nil, fmt.Errorf("failed to allocate CID: %w", err)
		}

		cfg.Extra = &QemuExtraConfig{
			CID: cid,
		}
	case *QemuExtraConfig:
		// Otherwise just allocate the configured CID to ensure it is free and in range.
		err := p.cidPool.AllocateExact(extraCfg.CID)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid provisioner configuration")
	}

	return p.sandbox.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (p *qemuProvisioner) Name() string {
	return "tdx-qemu"
}

func (p *qemuProvisioner) cleanup(cfg host.Config) {
	cid := cfg.Extra.(*QemuExtraConfig).CID // Ensured above.
	if !p.cidPool.Release(cid) {
		p.logger.Error("previously allocated CID was already released")
	}
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
				volume, ok := cfg.Component.Volumes[tdxCfg.Stage2Image]
				if !ok {
					return process.Config{}, fmt.Errorf("volume for '%s' not attached", tdxCfg.Stage2Image)
				}

				var err error
				stage2Image, err = p.createPersistentOverlayImage(stage2Image, stage2Format, volume)
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
		netArgs, err := p.createNetworkingConfig(cfg)
		if err != nil {
			return process.Config{}, fmt.Errorf("failed to create networking config: %w", err)
		}

		pcfg.Args = append(pcfg.Args, netArgs...)
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

// createNetworkingConfig generates QEMU networking configuration for a component.
func (p *qemuProvisioner) createNetworkingConfig(cfg host.Config) ([]string, error) {
	compCfg, _ := config.GlobalConfig.Runtime.GetComponent(cfg.ID, cfg.Component.ID())
	netdevOpts := []string{"user", "id=net0"}

	// Inbound forwarding.
	for _, netCfg := range compCfg.Networking.Incoming {
		var proto string
		switch netCfg.Protocol {
		case "tcp", "udp":
			proto = netCfg.Protocol
		case "":
			proto = "tcp"
		default:
			return nil, fmt.Errorf("network protocol '%s' not supported", netCfg.Protocol)
		}

		ip := netCfg.IP
		if ip == "" {
			ip = "0.0.0.0"
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return nil, fmt.Errorf("IP address '%s' is malformed", ip)
		}
		if parsedIP.IsUnspecified() {
			ip = ""
		} else {
			ip = parsedIP.String()
		}
		if parsedIP.To4() == nil {
			return nil, fmt.Errorf("IPv6 forwarding not supported")
		}

		if netCfg.SrcPort == 0 {
			return nil, fmt.Errorf("source port not specified")
		}
		dstPort := netCfg.DstPort
		if dstPort == 0 {
			dstPort = netCfg.SrcPort
		}

		netdevOpts = append(netdevOpts,
			fmt.Sprintf("hostfwd=%s:%s:%d-:%d", proto, ip, netCfg.SrcPort, dstPort),
		)
	}

	netArgs := []string{"-netdev", strings.Join(netdevOpts, ",")}
	return netArgs, nil
}

// createPersistentOverlayImage creates a persistent overlay image for the given backing image and
// returns the full path to the overlay image. In case the image already exists, it is reused.
//
// The format of the resulting image is always qcow2.
func (p *qemuProvisioner) createPersistentOverlayImage(image string, format string, volume *volume.Volume) (string, error) {
	switch _, err := os.Stat(volume.Path); {
	case err == nil:
		// Image already exists, perform a rebase operation to account for the backing file location
		// changing (e.g. due to an upgrade).
		cmd := exec.Command(
			defaultQemuImgPath,
			"info",
			"--output", "json",
			image,
		)
		var out strings.Builder
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to query base image: %s\n%w", out.String(), err)
		}
		var info struct {
			VirtualSize int `json:"virtual-size"`
		}
		if err := json.Unmarshal([]byte(out.String()), &info); err != nil {
			return "", fmt.Errorf("malformed base image metadata: %w", err)
		}

		cmd = exec.Command( //nolint: gosec
			defaultQemuImgPath,
			"rebase",
			"-u",
			"-f", "qcow2",
			"-b", image,
			"-F", format,
			volume.Path,
		)
		out.Reset()
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to rebase persistent overlay image: %s\n%w", out.String(), err)
		}

		// Perform a resize if needed.
		cmd = exec.Command( //nolint: gosec
			defaultQemuImgPath,
			"resize",
			volume.Path,
			fmt.Sprintf("%d", info.VirtualSize),
		)
		out.Reset()
		cmd.Stderr = &out
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to resize persistent overlay image: %s\n%w", out.String(), err)
		}
	case errors.Is(err, os.ErrNotExist):
		// Create the persistent overlay image.
		cmd := exec.Command( //nolint: gosec
			defaultQemuImgPath,
			"create",
			"-f", "qcow2",
			"-b", image,
			"-F", format,
			volume.Path,
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
	return volume.Path, nil
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
