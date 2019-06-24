package host

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/ctxsync"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx/aesm"
	cias "github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/common/version"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

const (
	// BackendSandboxed is the name of the sandboxed backend.
	BackendSandboxed = "sandboxed"
	// BackendUnconfined is the name of the no-sandbox backend.
	BackendUnconfined = "unconfined"

	// MetricsProxyKey is the key used to configure the metrics proxy.
	MetricsProxyKey = "metrics"
	// TracingProxyKey is the key used to configure the tracing proxy.
	TracingProxyKey = "tracing"

	// Worker connect timeout.
	workerConnectTimeout = 5 * time.Second
	// Worker runtime information request timeout.
	workerInfoTimeout = 1 * time.Second
	// Worker RAK initialization timeout.
	// This can take a long time in deployments that run multiple
	// nodes on a single machine, all sharing the same EPC.
	workerRAKTimeout = 60 * time.Second
	// Worker respawn delay.
	workerRespawnDelay = 1 * time.Second
	// Worker interrupt timeout.
	workerInterruptTimeout = 1 * time.Second
	// Worker attest interval.
	workerAttestInterval = 1 * time.Hour

	// Path to bubblewrap sandbox.
	workerBubblewrapBinary = "/usr/bin/bwrap"
	// Worker hostname
	workerHostname = "ekiden-worker"

	workerMountHostSocket = "/host.sock"
	workerMountWorkerBin  = "/worker"
	workerMountRuntimeBin = "/runtime"
	workerMountLibDir     = "/usr/lib"

	teeIntelSGXDevice = "/dev/isgx"
	teeIntelSGXSocket = "/var/run/aesmd/aesm.socket"
)

var (
	_ Host = (*sandboxedHost)(nil)

	// Paths for proxy sockets inside the sandbox.
	workerMountSocketMap = map[string]string{
		MetricsProxyKey: "/prometheus-proxy.sock",
		TracingProxyKey: "/jaeger-proxy.sock",
	}

	// Ports inside the sandbox to forward to the outside.
	workerProxyInnerAddrs = map[string]string{
		MetricsProxyKey: "127.0.0.1:8080",
		TracingProxyKey: "127.0.0.1:6831",
	}
)

// OnProcessStart is the function called after a worker process has been
// started.
type OnProcessStart func(*protocol.Protocol, *node.CapabilityTEE) error

// ProxySpecification contains all necessary details about a single proxy.
type ProxySpecification struct {
	// ProxyType is the type of this proxy ("stream" or "dgram").
	ProxyType string
	// SourceName is the path of the unix socket outside the sandbox.
	SourceName string
	// OuterAddr is the address to which the proxy is forwarding outside.
	OuterAddr string
	// mapName is the name of the unix socket inside the sandbox.
	mapName string
	// innerAddr is the address on which the proxy will listen inside the sandbox;
	// if bypass is true, innerAddr is the same as OuterAddr
	innerAddr string
	// bypass specifies if a proxy is needed or if the service will connect directly.
	bypass bool
}

type process struct {
	sync.Mutex

	process  *os.Process
	protocol *protocol.Protocol

	waitCh       <-chan error
	stopAttestCh chan struct{}
	quitAttestCh chan struct{}
	quitCh       chan error

	logger *logging.Logger

	capabilityTEE *node.CapabilityTEE
}

func waitOnProcess(p *os.Process) <-chan error {
	waitCh := make(chan error)
	go func() {
		ps, err := p.Wait()
		if err != nil {
			// Error while waiting on process.
			waitCh <- err
		} else if !ps.Success() {
			// Process terminated with a non-zero exit code.
			waitCh <- fmt.Errorf("process terminated with exit code %d", ps.Sys().(syscall.WaitStatus).ExitStatus())
		}

		close(waitCh)
	}()

	return waitCh
}

func (p *process) Kill() error {
	return p.process.Kill()
}

func (p *process) worker() {
	// Wait for the process to exit.
	err := <-p.waitCh

	if err == nil {
		p.logger.Warn("worker process terminated")
	} else {
		p.logger.Error("worker process terminated unexpectedly",
			"err", err,
		)
	}

	close(p.stopAttestCh)

	// Close connection after worker process has exited.
	p.protocol.Close()

	p.quitCh <- err
	close(p.quitCh)

	// Ensure the attestation worker is done.
	<-p.quitAttestCh

}

func (p *process) attestationWorker(h *sandboxedHost) {
	defer close(p.quitAttestCh)

	if p.capabilityTEE == nil {
		return
	}

	t := time.NewTicker(workerAttestInterval)
	defer t.Stop()

	for {
		select {
		case <-p.stopAttestCh:
			return
		case <-t.C:
		}

		p.logger.Info("regenerating CapabilityTEE")

		switch p.capabilityTEE.Hardware {
		case node.TEEHardwareIntelSGX:
			capabilityTEE, err := h.updateCapabilityTEESgx(p)
			if err != nil {
				p.logger.Error("failed to regenerate CapabilityTEE",
					"err", err,
				)
				continue
			}

			p.Lock()
			p.capabilityTEE = capabilityTEE
			p.Unlock()
		}
	}
}

func (p *process) getCapabilityTEE() *node.CapabilityTEE {
	p.Lock()
	defer p.Unlock()

	return p.capabilityTEE
}

func prepareSandboxArgs(hostSocket, workerBinary, runtimeBinary string, proxies map[string]ProxySpecification, hardware node.TEEHardware) ([]string, error) {
	// Prepare general arguments.
	args := []string{
		// Unshare all possible namespaces.
		"--unshare-all",
		// Drop all capabilities.
		"--cap-drop", "ALL",
		// Pass SECCOMP policy via file descriptor 4.
		"--seccomp", "4",
		// Ensure all workers have the same hostname.
		"--hostname", workerHostname,
		// Temporary directory.
		"--tmpfs", "/tmp",
		// A cut down /dev.
		"--dev", "/dev",
		// Host socket is bound as /host.sock.
		"--bind", hostSocket, workerMountHostSocket,
		// Worker binary is bound as /worker (read-only).
		"--ro-bind", workerBinary, workerMountWorkerBin,
		// Runtime binary is bound as /runtime.so (read-only).
		"--ro-bind", runtimeBinary, workerMountRuntimeBin,
		// Kill worker when node exits.
		"--die-with-parent",
		// Start new terminal session.
		"--new-session",
		// Change working directory to /.
		"--chdir", "/",
	}

	// Append any extra bind options for proxies.
	for _, pair := range proxies {
		args = append(args, "--bind", pair.SourceName, pair.mapName)
	}

	// Bind the TEE specific files.
	binaries := []string{workerBinary}

	switch hardware {
	case node.TEEHardwareIntelSGX:
		args = append(args, []string{
			"--dev-bind", teeIntelSGXDevice, teeIntelSGXDevice,
			"--dir", filepath.Dir(teeIntelSGXSocket),
			"--bind", teeIntelSGXSocket, teeIntelSGXSocket,
		}...)
	default:
		// We need to also inspect the runtime binary as it will be executed
		// as a regular process by the loader.
		binaries = append(binaries, runtimeBinary)
	}

	// Resolve worker binary library dependencies so we can mount them in.
	cache, err := loadDynlibCache()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load dynamic library loader cache")
	}
	libs, err := cache.ResolveLibraries(
		binaries,
		[]string{},
		"",
		os.Getenv("LD_LIBRARY_PATH"),
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve worker binary libraries")
	}

	// Bind all required libraries.
	for p, aliases := range libs {
		for _, alias := range aliases {
			mountDir := workerMountLibDir
			// The ld-linux-*.so library must be stored in /lib64 as otherwise the
			// binary will fail to start. All other libraries can be mounted to /usr/lib.
			if strings.HasPrefix(alias, "ld-linux") {
				mountDir = "/lib64"
			}

			args = append(args, "--ro-bind", p, filepath.Join(mountDir, alias))
		}
	}
	args = append(args, "--symlink", "/usr/lib", "/usr/lib64")

	// Worker arguments follow.
	args = append(args, "--", "/worker")

	return args, nil
}

func prepareWorkerArgs(hostSocket, runtimeBinary string, proxies map[string]ProxySpecification, hardware node.TEEHardware) []string {
	args := []string{
		"--host-socket", hostSocket,
	}
	for name, proxy := range proxies {
		if proxy.bypass {
			continue
		}
		args = append(args, fmt.Sprintf("--proxy-bind=%s,%s,%s,%s", proxy.ProxyType, name, proxy.innerAddr, proxy.mapName))
	}

	// Configure runtime type.
	switch hardware {
	case node.TEEHardwareIntelSGX:
		args = append(args, "--type", "sgxs")
	default:
		args = append(args, "--type", "elf")
	}

	args = append(args, runtimeBinary)
	return args
}

// HostRequest is an internal request to manager goroutine that is dispatched
// to the worker when a worker becomes available.
type hostRequest struct {
	ctx  context.Context
	body *protocol.Body
	ch   chan<- *hostResponse
}

// HostResponse is an internal response from the manager goroutine that is
// returned to the caller when a request has been dispatched to the worker.
type hostResponse struct {
	ch  <-chan *protocol.Body
	err error
}

// InterruptRequest is an internal request to manager goroutine that signals
// the worker should be interrupted.
type interruptRequest struct {
	ctx context.Context
	ch  chan<- error
}

type teeState struct {
	ias  *ias.IAS
	aesm *aesm.Client

	epidGID   uint32
	spid      cias.SPID
	quoteType *cias.SignatureType
}

// SandboxedHost is a worker Host that runs worker processes in a bubblewrap
// sandbox.
type sandboxedHost struct { // nolint: maligned
	workerBinary  string
	runtimeBinary string
	noSandbox     bool

	proxies     map[string]ProxySpecification
	teeHardware node.TEEHardware
	teeState    *teeState
	msgHandler  protocol.Handler

	stopCh chan struct{}
	quitCh chan struct{}

	activeWorker          *process
	activeWorkerAvailable *ctxsync.CancelableCond
	onProcessStart        OnProcessStart
	requestCh             chan *hostRequest
	interruptCh           chan *interruptRequest

	logger *logging.Logger
}

func (h *sandboxedHost) Name() string {
	return "sandboxed worker host"
}

func (h *sandboxedHost) WaitForCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error) {
	h.activeWorkerAvailable.L.Lock()
	defer h.activeWorkerAvailable.L.Unlock()
	for {
		activeWorker := h.activeWorker
		if activeWorker != nil {
			return activeWorker.getCapabilityTEE(), nil
		}
		if !h.activeWorkerAvailable.Wait(ctx) {
			return nil, errors.New("aborted by context")
		}
	}
}

func (h *sandboxedHost) Start() error {
	h.logger.Info("starting worker host")
	go h.manager()
	return nil
}

func (h *sandboxedHost) Stop() {
	close(h.stopCh)
}

func (h *sandboxedHost) Quit() <-chan struct{} {
	return h.quitCh
}

func (h *sandboxedHost) Cleanup() {
}

func (h *sandboxedHost) checkInfo(worker *process) error {
	ctx, cancel := context.WithTimeout(context.Background(), workerInfoTimeout)
	defer cancel()

	// Request information about the running runtime and abort if the protocol
	// version is incompatible.
	rsp, err := worker.protocol.Call(ctx, &protocol.Body{WorkerInfoRequest: &protocol.Empty{}})
	if err != nil || rsp.WorkerInfoResponse == nil {
		return errors.Wrap(err, "error while requesting runtime info")
	}

	info := rsp.WorkerInfoResponse
	if info.ProtocolVersion != version.RuntimeProtocol.ToU64() {
		h.logger.Error("runtime has incompatible protocol version",
			"version", info.ProtocolVersion,
			"expected_version", version.RuntimeProtocol.ToU64(),
		)
		return errors.New("incompatible runtime protocol version")
	}

	return nil
}

func (h *sandboxedHost) initCapabilityTEESgx(worker *process) error {
	ctx, cancel := context.WithTimeout(context.Background(), workerRAKTimeout)
	defer cancel()

	qi, err := h.teeState.aesm.InitQuote(ctx)
	if err != nil {
		return errors.Wrap(err, "worker: error while getting quote info from AESM")
	}
	h.teeState.epidGID = binary.LittleEndian.Uint32(qi.GID[:])

	if h.teeState.spid, err = h.teeState.ias.GetSPID(ctx); err != nil {
		return errors.Wrap(err, "worker: error while getting IAS SPID")
	}
	if h.teeState.quoteType, err = h.teeState.ias.GetQuoteSignatureType(ctx); err != nil {
		return errors.Wrap(err, "worker: error while getting IAS signature type")
	}

	if _, err = worker.protocol.Call(
		ctx,
		&protocol.Body{
			WorkerCapabilityTEERakInitRequest: &protocol.WorkerCapabilityTEERakInitRequest{
				TargetInfo: qi.TargetInfo,
			},
		},
	); err != nil {
		return errors.Wrap(err, "worker: error while initializing RAK")
	}

	return nil
}

func (h *sandboxedHost) updateCapabilityTEESgx(worker *process) (*node.CapabilityTEE, error) {
	ctx, cancel := context.WithTimeout(context.Background(), workerRAKTimeout)
	defer cancel()

	// Update the SigRL (Not cached, knowing if revoked is important).
	sigRL, err := h.teeState.ias.GetSigRL(ctx, h.teeState.epidGID)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting SigRL")
	}
	sigRL = cbor.FixSliceForSerde(sigRL)

	rakQuoteRes, err := worker.protocol.Call(
		ctx,
		&protocol.Body{
			WorkerCapabilityTEERakReportRequest: &protocol.Empty{},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting worker quote and public RAK")
	}
	rakPub := rakQuoteRes.WorkerCapabilityTEERakReportResponse.RakPub
	report := rakQuoteRes.WorkerCapabilityTEERakReportResponse.Report
	nonce := rakQuoteRes.WorkerCapabilityTEERakReportResponse.Nonce

	quote, err := h.teeState.aesm.GetQuote(
		ctx,
		report,
		*h.teeState.quoteType,
		h.teeState.spid,
		make([]byte, 16),
		sigRL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while getting quote")
	}

	avr, sig, chain, err := h.teeState.ias.VerifyEvidence(ctx, quote, nil, nonce)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while verifying attestation evidence")
	}

	avrBundle := cias.AVRBundle{
		Body:             avr,
		CertificateChain: chain,
		Signature:        sig,
	}
	_, err = worker.protocol.Call(
		ctx,
		&protocol.Body{
			WorkerCapabilityTEERakAvrRequest: &protocol.WorkerCapabilityTEERakAvrRequest{
				AVR: avrBundle,
			},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while configuring AVR")
	}

	attestation := avrBundle.MarshalCBOR()
	capabilityTEE := &node.CapabilityTEE{
		Hardware:    node.TEEHardwareIntelSGX,
		RAK:         rakPub,
		Attestation: attestation,
	}

	return capabilityTEE, nil
}

func (h *sandboxedHost) MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error) {
	respCh := make(chan *hostResponse, 1)

	// Send internal request to the manager goroutine.
	select {
	case h.requestCh <- &hostRequest{ctx, body, respCh}:
	case <-ctx.Done():
		return nil, context.Canceled
	}

	// Wait for response from the manager goroutine.
	select {
	case resp := <-respCh:
		return resp.ch, resp.err
	case <-ctx.Done():
		return nil, context.Canceled
	}
}

func (h *sandboxedHost) InterruptWorker(ctx context.Context) error {
	respCh := make(chan error, 1)

	// Send internal request to the manager goroutine.
	select {
	case h.interruptCh <- &interruptRequest{ctx, respCh}:
	case <-ctx.Done():
		return context.Canceled
	}

	// Wait for response from the manager goroutine.
	select {
	case resp := <-respCh:
		return resp
	case <-ctx.Done():
		return context.Canceled
	}
}

func (h *sandboxedHost) spawnWorker() (*process, error) { // nolint: gocyclo
	h.logger.Info("spawning worker",
		"worker_binary", h.workerBinary,
		"runtime_binary", h.runtimeBinary,
	)

	// Create a temporary worker directory.
	workerDir, err := ioutil.TempDir("", "ekiden-worker")
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create temporary directory")
	}
	// We can remove the worker directory after the worker has been started as it
	// has been mounted into the sandbox and is no longer needed.
	defer os.RemoveAll(workerDir)

	// Create unix socket.
	hostSocket := filepath.Join(workerDir, "host.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: hostSocket})
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create host socket")
	}

	// Since we only accept a single connection, we should close the listener
	// in any case.
	defer listener.Close()

	// Start the worker (optionally in a sandbox).
	var sandboxArgs []string
	var sandboxBinary string
	var workerArgs []string
	if h.noSandbox {
		sandboxBinary = h.workerBinary
		workerArgs = prepareWorkerArgs(
			hostSocket,
			h.runtimeBinary,
			h.proxies,
			h.teeHardware,
		)
	} else {
		sandboxArgs = []string{
			"--args", "3",
			"--",
			workerMountWorkerBin,
		}
		sandboxBinary = workerBubblewrapBinary
		workerArgs = prepareWorkerArgs(
			workerMountHostSocket,
			workerMountRuntimeBin,
			h.proxies,
			h.teeHardware,
		)
	}

	args := append(sandboxArgs, workerArgs...)
	cmd := exec.Command(sandboxBinary, args...)
	// Forward stdout and stderr.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var sandboxCmdPipeW *os.File
	var sandboxSeccompPipeW *os.File
	if !h.noSandbox {
		// Create a pipe for passing the sandbox arguments. The read end of the
		// pipe is passed to the child process.
		cmdPipeR, cmdPipeW, perr := os.Pipe()
		if perr != nil {
			return nil, errors.Wrap(perr, "worker: failed to create pipe (args)")
		}

		// Create a pipe for passing the sandbox SECCOMP policy. The read end of
		// the pipe is passed to the child process.
		seccompPipeR, seccompPipeW, perr := os.Pipe()
		if perr != nil {
			return nil, errors.Wrap(perr, "worker: failed to create pipe (seccomp)")
		}

		// Pass the arguments pipe file descriptor.
		// NOTE: Entry i becomes file descriptor 3+i.
		cmd.ExtraFiles = []*os.File{cmdPipeR, seccompPipeR}

		sandboxCmdPipeW = cmdPipeW
		sandboxSeccompPipeW = seccompPipeW
	}

	if cerr := cmd.Start(); cerr != nil {
		return nil, errors.Wrap(cerr, "worker: failed to start worker process")
	}

	// Ensure that the spawned process gets killed in case of errors.
	haveErrors := true
	defer func() {
		if haveErrors {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	if !h.noSandbox {
		// Instruct the sandbox how to prepare itself.
		sandboxArgs, err := prepareSandboxArgs(hostSocket, h.workerBinary, h.runtimeBinary, h.proxies, h.teeHardware) // nolint: govet
		if err != nil {
			return nil, errors.Wrap(err, "worker: error while preparing sandbox args")
		}
		for _, arg := range sandboxArgs {
			if _, werr := sandboxCmdPipeW.Write([]byte(arg + "\x00")); werr != nil {
				return nil, errors.Wrap(werr, "worker: error while sending args to sandbox")
			}
		}
		if werr := sandboxCmdPipeW.Close(); werr != nil {
			return nil, errors.Wrap(werr, "worker: error while sending args to sandbox")
		}

		// Generate SECCOMP policy and pass it to the sandbox.
		err = generateSeccompPolicy(sandboxSeccompPipeW)
		if err != nil {
			return nil, errors.Wrap(err, "worker: error while generating seccomp policy")
		}
		if werr := sandboxSeccompPipeW.Close(); werr != nil {
			return nil, errors.Wrap(werr, "worker: error while sending seccomp policy to sandbox")
		}
	}

	// Wait for the worker to connect.
	h.logger.Info("waiting for worker to connect",
		"worker_pid", cmd.Process.Pid,
	)

	// Spawn goroutine that waits for the sync FD to be closed. We only need it while
	// we wait for the connection to be accepted as later we can simply wait on the
	// sandbox process to exit.
	waitCh := waitOnProcess(cmd.Process)

	// Spawn goroutine that waits for a connection to be established.
	connCh := make(chan interface{})
	go func() {
		lerr := listener.SetDeadline(time.Now().Add(workerConnectTimeout))
		if lerr != nil {
			connCh <- lerr
			return
		}
		conn, lerr := listener.Accept()
		if lerr != nil {
			connCh <- lerr
			return
		}

		connCh <- conn
		close(connCh)
	}()

	var conn net.Conn
	select {
	case res := <-connCh:
		// Got a connection or timed out while accepting a connection.
		switch r := res.(type) {
		case error:
			return nil, errors.Wrap(r, "worker: error while accepting worker connection")
		case net.Conn:
			conn = r
		default:
			panic("invalid type")
		}
	case werr := <-waitCh:
		// Worker has terminated before a connection was accepted.
		h.logger.Debug("worker process exited unexpectedly",
			"worker_pid", cmd.Process.Pid,
			"err", werr,
		)

		return nil, errors.New("worker: terminated while waiting for connection")
	}

	h.logger.Info("worker connected",
		"worker_pid", cmd.Process.Pid,
	)

	// Spawn protocol instance on the given connection.
	logger := h.logger.With("worker_pid", cmd.Process.Pid)
	proto, err := protocol.New(logger, conn, h.msgHandler)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while instantiating protocol")
	}

	p := &process{
		process:      cmd.Process,
		protocol:     proto,
		quitCh:       make(chan error),
		stopAttestCh: make(chan struct{}),
		quitAttestCh: make(chan struct{}),
		waitCh:       waitCh,
		logger:       logger,
	}
	go p.worker()

	// Check runtime version information.
	if err = h.checkInfo(p); err != nil {
		return nil, errors.Wrap(err, "worker: error checking runtime info")
	}

	// Initialize the worker's CapabilityTEE.
	switch h.teeHardware {
	case node.TEEHardwareInvalid:
		// No initialization needed.
		p.capabilityTEE = nil
	case node.TEEHardwareIntelSGX:
		if err = h.initCapabilityTEESgx(p); err != nil {
			return nil, errors.Wrap(err, "worker: error initializing SGX CapabilityTEE")
		}
		if p.capabilityTEE, err = h.updateCapabilityTEESgx(p); err != nil {
			return nil, errors.Wrap(err, "worker: error updating SGX CapabilityTEE")
		}
	default:
		return nil, node.ErrInvalidTEEHardware
	}

	if h.onProcessStart != nil {
		if err = h.onProcessStart(proto, p.capabilityTEE); err != nil {
			return nil, errors.Wrap(err, "worker: process post-start hook failed")
		}
	}

	go p.attestationWorker(h)

	haveErrors = false

	return p, nil
}

func (h *sandboxedHost) spawnAndReplaceWorker() error {
	worker, err := h.spawnWorker()
	if err != nil {
		return err
	}

	h.activeWorkerAvailable.L.Lock()
	h.activeWorker = worker
	h.activeWorkerAvailable.Broadcast()
	h.activeWorkerAvailable.L.Unlock()

	return nil
}

func (h *sandboxedHost) handleInterruptWorker(ctx context.Context) error {
	h.logger.Warn("interrupting worker")

	// First attempt to gracefully interrupt the worker by sending a request.
	ictx, cancel := context.WithTimeout(ctx, workerInterruptTimeout)
	defer cancel()

	response, err := h.activeWorker.protocol.Call(ictx, &protocol.Body{WorkerAbortRequest: &protocol.Empty{}})
	if err == nil && response.WorkerAbortResponse != nil {
		// Successful response, assume worker is done.
		return nil
	}

	h.logger.Warn("graceful interrupt failed, killing worker")

	// Failed to gracefully interrupt the worker. Kill the worker and it
	// will be automatically restarted by the manager after it dies.
	_ = h.activeWorker.Kill()

	// Wait for the worker to terminate. We do this here so that the response
	// to the interrupt request is only sent after the new worker has been
	// respawned and is ready to use.
	select {
	case <-h.activeWorker.quitCh:
	case <-ctx.Done():
		return context.Canceled
	}

	// Respawn worker.
	// NOTE: This may violate the context deadline, but interrupting this
	//       method does not make sense. The method uses its own deadlines
	//       so it should never block forever.
	return h.spawnAndReplaceWorker()
}

func (h *sandboxedHost) manager() {
	// Make sure that a worker is always available.
	wantWorker := true
	needSpawnDelay := false
ManagerLoop:
	for {
		// Wait for the worker to terminate.
	WaitWorkerToTerminate:
		for h.activeWorker != nil {
			select {
			case rq := <-h.requestCh:
				// Forward request to given worker and send back the response.
				ch, err := h.activeWorker.protocol.MakeRequest(rq.ctx, rq.body)
				rq.ch <- &hostResponse{ch, err}
				close(rq.ch)
				continue WaitWorkerToTerminate
			case intr := <-h.interruptCh:
				// Attempt to interrupt the worker.
				intr.ch <- h.handleInterruptWorker(intr.ctx)
				close(intr.ch)
				continue WaitWorkerToTerminate
			case err := <-h.activeWorker.quitCh:
				// Worker has terminated.
				h.logger.Warn("worker terminated")
				needSpawnDelay = true

				if err != nil {
					h.logger.Error("failed to wait on worker to terminate",
						"err", err,
					)
				}
			case <-h.stopCh:
				// Termination requested.
				h.logger.Info("termination requested")
				wantWorker = false

				// Kill the worker and wait for it to terminate.
				_ = h.activeWorker.Kill()
				<-h.activeWorker.quitCh
			}

			h.activeWorkerAvailable.L.Lock()
			h.activeWorker = nil
			h.activeWorkerAvailable.L.Unlock()
		}

		if !wantWorker {
			break
		}

		// Spawn new worker process after a respawn delay.
		if needSpawnDelay {
			select {
			case <-time.After(workerRespawnDelay):
			case <-h.stopCh:
				// Termination requested while no worker is spawned.
				h.logger.Info("termination requested")
				break ManagerLoop
			}
		}

		err := h.spawnAndReplaceWorker()
		if err != nil {
			h.logger.Error("failed to spawn new worker",
				"err", err,
			)
			needSpawnDelay = true
			continue
		}
	}

	close(h.quitCh)
}

// NewSandboxedHost creates a new sandboxed worker host.
func NewSandboxedHost(
	name string,
	workerBinary string,
	runtimeBinary string,
	proxies map[string]ProxySpecification,
	teeHardware node.TEEHardware,
	ias *ias.IAS,
	msgHandler protocol.Handler,
	onProcessStart OnProcessStart,
	noSandbox bool,
) (Host, error) {
	if workerBinary == "" {
		return nil, errors.New("worker binary not configured")
	}
	if runtimeBinary == "" {
		return nil, errors.New("runtime binary not configured")
	}

	knownProxies := make(map[string]ProxySpecification)
	for name, mappedSocket := range workerMountSocketMap {
		if proxy, ok := proxies[name]; ok {
			proxy.mapName = mappedSocket
			if noSandbox {
				proxy.innerAddr = proxy.OuterAddr
			} else {
				proxy.innerAddr = workerProxyInnerAddrs[name]
			}
			proxy.bypass = noSandbox
			knownProxies[name] = proxy
		}
	}

	var aesmClient *aesm.Client
	switch teeHardware {
	case node.TEEHardwareIntelSGX:
		aesmClient = aesm.NewClient(teeIntelSGXSocket)
	default:
	}

	host := &sandboxedHost{
		workerBinary:  workerBinary,
		runtimeBinary: runtimeBinary,
		noSandbox:     noSandbox,
		proxies:       knownProxies,
		teeHardware:   teeHardware,
		teeState: &teeState{
			ias:  ias,
			aesm: aesmClient,
		},
		msgHandler:            msgHandler,
		quitCh:                make(chan struct{}),
		stopCh:                make(chan struct{}),
		activeWorkerAvailable: ctxsync.NewCancelableCond(new(sync.Mutex)),
		onProcessStart:        onProcessStart,
		requestCh:             make(chan *hostRequest, 10),
		interruptCh:           make(chan *interruptRequest, 10),
		logger:                logging.GetLogger("worker/common/host/sandboxed").With("name", name),
	}
	return host, nil
}
