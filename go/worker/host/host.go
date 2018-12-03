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
	"time"

	"git.schwanenlied.me/yawning/dynlib.git"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	cias "github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

var (
	_ service.BackgroundService = (*Host)(nil)
)

const (
	// Worker connect timeout (in seconds).
	workerConnectTimeout = 5
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

// Host is a worker host managing multiple workers.
type Host struct {
	workerBinary  string
	runtimeBinary string
	cacheDir      string

	storage storage.Backend
	ias     *ias.IAS

	stopCh chan struct{}
	quitCh chan struct{}

	// TODO: Add support for multiple workers.
	activeWorker *process

	logger *logging.Logger
}

// Name returns the service name.
func (h *Host) Name() string {
	return "worker host"
}

// Start starts the service.
func (h *Host) Start() error {
	// TODO: Remove this after it is an error if no worker binary is configured.
	if h.workerBinary == "" {
		h.logger.Warn("not starting worker host as worker binary is not configured")
		return nil
	}

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
	ctx := context.Background()

	quoteType, err := h.ias.GetQuoteSignatureType(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while getting IAS signature type")
	}

	spid, err := h.ias.GetSPID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while getting IAS SPID")
	}

	gidCh, err := worker.protocol.MakeRequest(&protocol.Body{WorkerCapabilityTEEGidRequest: &protocol.Empty{}})
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting worker EPID group")
	}
	gidRes := <-gidCh
	gid := gidRes.WorkerCapabilityTEEGidResponse.Gid

	sigRL, err := h.ias.GetSigRL(ctx, binary.LittleEndian.Uint32(gid[:]))
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting SigRL")
	}

	rakQuoteCh, err := worker.protocol.MakeRequest(&protocol.Body{WorkerCapabilityTEERakQuoteRequest: &protocol.WorkerCapabilityTEERakQuoteRequest{
		QuoteType: uint32(*quoteType),
		Spid:      spid,
		SigRL:     sigRL,
	}})
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while requesting worker quote and public RAK")
	}
	rakQuoteRes := <-rakQuoteCh
	rakPub := signature.PublicKey{}
	err = rakPub.UnmarshalBinary(rakQuoteRes.WorkerCapabilityTEERakQuoteResponse.RakPub[:])
	if err != nil {
		return nil, errors.Wrap(err, "worker: error while unmarshalling public RAK")
	}
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
	handler := newHostHandler(h.storage, h.ias)
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

	// Initialize the worker's RAK.
	capabilityTEE, err := h.initCapabilityTEESgx(p)
	if err != nil {
		return nil, errors.Wrap(err, "worker: error initializing SGX CapabilityTEE")
	}

	p.capabilityTEE = capabilityTEE

	haveErrors = false

	return p, nil
}

func (h *Host) manager() {
	// Make sure that a worker is always available.
	// TODO: Support multiple workers.
	wantWorker := true
	needSpawnDelay := false
	for {
		// Wait for the worker to terminate.
		if h.activeWorker != nil {
			select {
			case err := <-h.activeWorker.quitCh:
				h.logger.Warn("worker terminated")
				needSpawnDelay = true

				if err != nil {
					h.logger.Error("failed to wait on worker to terminate",
						"err", err,
					)
				}
			case <-h.stopCh:
				h.logger.Info("termination requested")
				wantWorker = false

				// Kill the worker and wait for it to terminate.
				_ = h.activeWorker.Kill()
				<-h.activeWorker.quitCh
			}

			h.activeWorker = nil
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
			continue
		}

		h.activeWorker = worker
	}

	close(h.quitCh)
}

func newHost(workerBinary, runtimeBinary, cacheDir string, storage storage.Backend, ias *ias.IAS) (*Host, error) {
	// TODO: Make it an error if worker binary is not configured.
	if workerBinary != "" {
		if runtimeBinary == "" {
			return nil, errors.New("runtime binary not configured")
		}
		if cacheDir == "" {
			return nil, errors.New("worker cache directory not configured")
		}
	}

	host := &Host{
		workerBinary:  workerBinary,
		runtimeBinary: runtimeBinary,
		cacheDir:      cacheDir,
		storage:       storage,
		ias:           ias,
		quitCh:        make(chan struct{}),
		stopCh:        make(chan struct{}),
		logger:        logging.GetLogger("worker/host"),
	}

	return host, nil
}
