package host

import (
	"context"
	"encoding/binary"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"git.schwanenlied.me/yawning/dynlib.git"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ctxsync"
	cias "github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/enclaverpc"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

var (
	_ service.BackgroundService = (*Host)(nil)
)

const (
	// Worker connect timeout (in seconds).
	workerConnectTimeout = 5
	// Worker RAK initialization timeout (in seconds).
	workerRAKTimeout = 5
	// Worker respawn delay (in seconds).
	workerRespawnDelay = 1

	// Path to bubblewrap sandbox.
	workerBubblewrapBinary = "/usr/bin/bwrap"
	// Worker hostname
	workerHostname = "ekiden-worker"

	workerMountHostSocket = "/host.sock"
	workerMountCacheDir   = "/cache"
	workerMountWorkerBin  = "/worker"
	workerMountRuntimeBin = "/runtime.so"
	workerMountLibDir     = "/usr/lib"
)

type process struct {
	process  *os.Process
	protocol *protocol.Protocol

	quitCh chan error

	logger *logging.Logger

	capabilityTEE *node.CapabilityTEE
}

func (p *process) Kill() error {
	return p.process.Kill()
}

func (p *process) worker() {
	// Wait for the process to exit.
	_, err := p.process.Wait()

	p.logger.Warn("worker process terminated")

	// Close connection after worker process has exited.
	p.protocol.Close()

	p.quitCh <- err
	close(p.quitCh)
}

func prepareSandboxArgs(hostSocket, workerBinary, runtimeBinary, cacheDir string) ([]string, error) {
	// Prepare general arguments.
	args := []string{
		// Unshare all possible namespaces.
		"--unshare-all",
		// TODO: Proxy prometheus and tracing over an AF_LOCAL socket to avoid this.
		"--share-net",
		"--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
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
		// Cache directory is bound as /cache (writable).
		"--bind", cacheDir, workerMountCacheDir,
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

	// Resolve worker binary library dependencies so we can mount them in.
	cache, err := dynlib.LoadCache()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load dynamic library loader cache")
	}
	libs, err := cache.ResolveLibraries(
		[]string{workerBinary},
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

			args = append(args, "--ro-bind", p, path.Join(mountDir, alias))
		}
	}

	// Worker arguments follow.
	args = append(args, "--", "/worker")

	return args, nil
}

func prepareWorkerArgs() ([]string, error) {
	return []string{
		"--host-socket", workerMountHostSocket,
		"--cache-dir", workerMountCacheDir,
		workerMountRuntimeBin,
	}, nil
}

// Request is an internal request to manager goroutine that is dispatched
// to the worker when a worker becomes available.
type hostRequest struct {
	ctx  context.Context
	body *protocol.Body
	ch   chan<- *hostResponse
}

// Response is an internal response from the manager goroutine that is
// returned to the caller when a request has been dispatched to the worker.
type hostResponse struct {
	ch  <-chan *protocol.Body
	err error
}

// Host is a worker host managing multiple workers.
type Host struct {
	workerBinary  string
	runtimeBinary string
	cacheDir      string

	storage     storage.Backend
	teeHardware node.TEEHardware
	ias         *ias.IAS
	keyManager  *enclaverpc.Client

	stopCh chan struct{}
	quitCh chan struct{}

	activeWorker          *process
	activeWorkerAvailable *ctxsync.CancelableCond
	requestCh             chan *hostRequest

	logger *logging.Logger
}

// Name returns the service name.
func (h *Host) Name() string {
	return "worker host"
}

// WaitForCapabilityTEE gets the active worker's CapabilityTEE,
// blocking if the active worker is not yet available. The returned
// CapabilityTEE may be out of date by the time this function returns.
func (h *Host) WaitForCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error) {
	h.activeWorkerAvailable.L.Lock()
	defer h.activeWorkerAvailable.L.Unlock()
	for {
		activeWorker := h.activeWorker
		if activeWorker != nil {
			return activeWorker.capabilityTEE, nil
		}
		if !h.activeWorkerAvailable.Wait(ctx) {
			return nil, errors.New("aborted by context")
		}
	}
}

// Start starts the service.
func (h *Host) Start() error {
	h.logger.Info("starting worker host")
	go h.manager()
	return nil
}

// Stop halts the service.
func (h *Host) Stop() {
	close(h.stopCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (h *Host) Quit() <-chan struct{} {
	return h.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (h *Host) Cleanup() {
}

// Initialize a CapabilityTEE for a worker.
func (h *Host) initCapabilityTEESgx(worker *process) (*node.CapabilityTEE, error) {
	ctx, cancel := context.WithTimeout(context.Background(), workerRAKTimeout*time.Second)
	defer cancel()

	quoteType, err := h.ias.GetQuoteSignatureType(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while getting IAS signature type")
	}

	spid, err := h.ias.GetSPID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while getting IAS SPID")
	}

	gidRes, err := worker.protocol.Call(
		ctx,
		&protocol.Body{
			WorkerCapabilityTEEGidRequest: &protocol.Empty{},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting worker EPID group")
	}
	gid := gidRes.WorkerCapabilityTEEGidResponse.Gid

	sigRL, err := h.ias.GetSigRL(ctx, binary.LittleEndian.Uint32(gid[:]))
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting SigRL")
	}

	rakQuoteRes, err := worker.protocol.Call(
		ctx,
		&protocol.Body{
			WorkerCapabilityTEERakQuoteRequest: &protocol.WorkerCapabilityTEERakQuoteRequest{
				QuoteType: uint32(*quoteType),
				SPID:      spid,
				SigRL:     sigRL,
			},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting worker quote and public RAK")
	}
	rakPub := rakQuoteRes.WorkerCapabilityTEERakQuoteResponse.RakPub
	quote := rakQuoteRes.WorkerCapabilityTEERakQuoteResponse.Quote

	avr, sig, chain, err := h.ias.VerifyEvidence(ctx, quote, nil)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while verifying attestation evidence")
	}

	avrBundle := cias.AVRBundle{
		Body:             avr,
		CertificateChain: chain,
		Signature:        sig,
	}
	attestation := avrBundle.MarshalCBOR()
	capabilityTEE := &node.CapabilityTEE{
		Hardware:    node.TEEHardwareIntelSGX,
		RAK:         rakPub,
		Attestation: attestation,
	}

	return capabilityTEE, nil
}

// MakeRequest sends a request to the worker process.
func (h *Host) MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error) {
	respCh := make(chan *hostResponse, 1)

	// Send internal request to the manager goroutine.
	select {
	case h.requestCh <- &hostRequest{ctx, body, respCh}:
	case <-ctx.Done():
		return nil, errors.New("aborted by context")
	}

	// Wait for response from the manager goroutine.
	select {
	case resp := <-respCh:
		return resp.ch, resp.err
	case <-ctx.Done():
		return nil, errors.New("aborted by context")
	}
}

func (h *Host) spawnWorker() (*process, error) {
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

	// Ensure worker cache directory exists.
	err = os.MkdirAll(h.cacheDir, 0700)
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create worker cache directory")
	}

	// Create a pipe for passing the sandbox arguments. The read end of the
	// pipe is passed to the child process.
	cmdPipeR, cmdPipeW, err := os.Pipe()
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create pipe (args)")
	}

	// Create a pipe for passing the sandbox SECCOMP policy. The read end of
	// the pipe is passed to the child process.
	seccompPipeR, seccompPipeW, err := os.Pipe()
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create pipe (seccomp)")
	}

	// Create unix socket.
	hostSocket := path.Join(workerDir, "host.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: hostSocket})
	if err != nil {
		return nil, errors.Wrap(err, "worker: failed to create host socket")
	}

	// Since we only accept a single connection, we should close the listener
	// in any case.
	defer listener.Close()

	// Start the worker sandbox.
	bwrapArgs := []string{
		"--args", "3",
		"--",
		workerMountWorkerBin,
	}
	workerArgs, err := prepareWorkerArgs()
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while preparing worker args")
	}
	args := append(bwrapArgs, workerArgs...)
	cmd := exec.Command(workerBubblewrapBinary, args...)
	// Forward stdout and stderr.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Pass the arguments pipe file descriptor.
	// NOTE: Entry i becomes file descriptor 3+i.
	cmd.ExtraFiles = []*os.File{cmdPipeR, seccompPipeR}
	if cerr := cmd.Start(); cerr != nil {
		return nil, errors.Wrap(cerr, "worker: failed to start sandbox")
	}

	// Ensure that the spawned process gets killed in case of errors.
	haveErrors := true
	defer func() {
		if haveErrors {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	// Instruct the sandbox how to prepare itself.
	sandboxArgs, err := prepareSandboxArgs(hostSocket, h.workerBinary, h.runtimeBinary, h.cacheDir)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while preparing sandbox args")
	}
	for _, arg := range sandboxArgs {
		if _, werr := cmdPipeW.Write([]byte(arg + "\x00")); werr != nil {
			return nil, errors.Wrap(werr, "worker: error while sending args to sandbox")
		}
	}
	if werr := cmdPipeW.Close(); werr != nil {
		return nil, errors.Wrap(werr, "worker: error while sending args to sandbox")
	}

	// Generate SECCOMP policy and pass it to the sandbox.
	err = generateSeccompPolicy(seccompPipeW)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while generating seccomp policy")
	}
	if werr := seccompPipeW.Close(); werr != nil {
		return nil, errors.Wrap(werr, "worker: error while sending seccomp policy to sandbox")
	}

	// Wait for the worker to connect.
	h.logger.Info("waiting for worker to connect",
		"worker_pid", cmd.Process.Pid,
	)

	err = listener.SetDeadline(time.Now().Add(workerConnectTimeout * time.Second))
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while accepting worker connection")
	}
	conn, err := listener.Accept()
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while accepting worker connection")
	}

	h.logger.Info("worker connected",
		"worker_pid", cmd.Process.Pid,
	)

	// Spawn protocol instance on the given connection.
	logger := h.logger.With("worker_pid", cmd.Process.Pid)
	handler := newHostHandler(h.storage, h.ias, h.keyManager)
	proto, err := protocol.New(logger, conn, handler)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while instantiating protocol")
	}

	p := &process{
		process:  cmd.Process,
		protocol: proto,
		quitCh:   make(chan error),
		logger:   logger,
	}
	go p.worker()

	// Initialize the worker's CapabilityTEE.
	switch h.teeHardware {
	case node.TEEHardwareInvalid:
		// No initialization needed.
	case node.TEEHardwareIntelSGX:
		capabilityTEE, err := h.initCapabilityTEESgx(p)
		if err != nil {
			return nil, errors.Wrap(err, "worker: error initializing SGX CapabilityTEE")
		}
		p.capabilityTEE = capabilityTEE
	default:
		return nil, node.ErrInvalidTEEHardware
	}

	haveErrors = false

	return p, nil
}

func (h *Host) manager() {
	// Make sure that a worker is always available.
	wantWorker := true
	needSpawnDelay := false
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
			time.Sleep(time.Second * workerRespawnDelay)
		}

		worker, err := h.spawnWorker()
		if err != nil {
			h.logger.Error("failed to spawn new worker",
				"err", err,
			)
			needSpawnDelay = true
			continue
		}

		h.activeWorkerAvailable.L.Lock()
		h.activeWorker = worker
		h.activeWorkerAvailable.Broadcast()
		h.activeWorkerAvailable.L.Unlock()
	}

	close(h.quitCh)
}

func New(
	workerBinary string,
	runtimeBinary string,
	cacheDir string,
	runtimeID signature.PublicKey,
	storage storage.Backend,
	teeHardware node.TEEHardware,
	ias *ias.IAS,
	keyManager *enclaverpc.Client,
) (*Host, error) {
	if workerBinary == "" {
		return nil, errors.New("worker binary not configured")
	}
	if runtimeBinary == "" {
		return nil, errors.New("runtime binary not configured")
	}
	if cacheDir == "" {
		return nil, errors.New("worker cache directory not configured")
	}

	host := &Host{
		workerBinary:          workerBinary,
		runtimeBinary:         runtimeBinary,
		cacheDir:              cacheDir,
		storage:               storage,
		teeHardware:           teeHardware,
		ias:                   ias,
		keyManager:            keyManager,
		quitCh:                make(chan struct{}),
		stopCh:                make(chan struct{}),
		activeWorkerAvailable: ctxsync.NewCancelableCond(new(sync.Mutex)),
		requestCh:             make(chan *hostRequest, 10),
		logger:                logging.GetLogger("worker/host").With("runtime_id", runtimeID),
	}

	return host, nil
}
