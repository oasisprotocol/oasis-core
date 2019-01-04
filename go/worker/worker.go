package worker

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/committee"
	"github.com/oasislabs/ekiden/go/worker/enclaverpc"
	"github.com/oasislabs/ekiden/go/worker/host"
	"github.com/oasislabs/ekiden/go/worker/ias"
	"github.com/oasislabs/ekiden/go/worker/p2p"
)

// RuntimeConfig is a single runtime's configuration.
type RuntimeConfig struct {
	ID     signature.PublicKey
	Binary string
}

// Config is the worker configuration.
type Config struct {
	Backend      string
	Committee    committee.Config
	P2PPort      uint16
	TEEHardware  node.TEEHardware
	WorkerBinary string
	CacheDir     string
	Runtimes     []RuntimeConfig
}

// Runtime is a single runtime.
type Runtime struct {
	id signature.PublicKey

	workerHost host.Host
	node       *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	return r.node
}

// Worker is a worker handling many runtimes.
type Worker struct {
	enabled bool
	cfg     Config

	identity   *identity.Identity
	storage    storage.Backend
	roothash   roothash.Backend
	registry   registry.Backend
	epochtime  epochtime.Backend
	scheduler  scheduler.Backend
	ias        *ias.IAS
	keyManager *enclaverpc.Client
	p2p        *p2p.P2P
	grpc       *grpc.Server

	runtimes map[signature.MapKey]*Runtime

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "compute worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for the gRPC server and all runtimes to terminate.
	go func() {
		defer close(w.quitCh)
		defer (w.cancelCtx)()

		for _, rt := range w.runtimes {
			<-rt.workerHost.Quit()
			<-rt.node.Quit()
		}

		<-w.grpc.Quit()
	}()

	// Wait for all runtimes to be initialized.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

		close(w.initCh)
	}()

	// Start client gRPC server.
	if err := w.grpc.Start(); err != nil {
		return err
	}

	// Start runtime services.
	for _, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", rt.id,
		)

		if err := rt.workerHost.Start(); err != nil {
			return err
		}
		if err := rt.node.Start(); err != nil {
			return err
		}
	}

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	for _, rt := range w.runtimes {
		w.logger.Info("stopping services for runtime",
			"runtime_id", rt.id,
		)

		rt.node.Stop()
		rt.workerHost.Stop()
	}

	w.grpc.Stop()
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
	if !w.enabled {
		return
	}

	for _, rt := range w.runtimes {
		rt.node.Cleanup()
		rt.workerHost.Cleanup()
	}

	w.grpc.Cleanup()
}

// Initialized returns a channel that will be closed when the worker is
// initialized and ready to service requests.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetConfig returns the worker's configuration.
func (w *Worker) GetConfig() Config {
	return w.cfg
}

// GetRuntime returns a registered runtime.
//
// In case the runtime with the specified id was not registered it
// returns nil.
func (w *Worker) GetRuntime(id signature.PublicKey) *Runtime {
	rt, ok := w.runtimes[id.ToMapKey()]
	if !ok {
		return nil
	}

	return rt
}

func (w *Worker) newWorkerHost(cfg *Config, rtCfg *RuntimeConfig) (h host.Host, err error) {
	switch strings.ToLower(cfg.Backend) {
	case host.BackendSandboxed:
		h, err = host.NewSandboxedHost(
			cfg.WorkerBinary,
			rtCfg.Binary,
			path.Join(cfg.CacheDir, rtCfg.ID.String()),
			rtCfg.ID,
			w.storage,
			cfg.TEEHardware,
			w.ias,
			w.keyManager,
		)
	case host.BackendMock:
		h, err = host.NewMockHost()
	default:
		err = fmt.Errorf("unsupported worker host backend: '%v'", cfg.Backend)
	}

	return
}

func (w *Worker) registerRuntime(cfg *Config, rtCfg *RuntimeConfig) error {
	w.logger.Info("registering new runtime",
		"runtime_id", rtCfg.ID,
	)

	// Create worker host for the given runtime.
	workerHost, err := w.newWorkerHost(cfg, rtCfg)
	if err != nil {
		return err
	}

	// Create committee node for the given runtime.
	node, err := committee.NewNode(
		rtCfg.ID,
		w.identity,
		w.storage,
		w.roothash,
		w.registry,
		w.epochtime,
		w.scheduler,
		workerHost,
		w.p2p,
		cfg.Committee,
	)
	if err != nil {
		return err
	}

	rt := &Runtime{
		id:         rtCfg.ID,
		workerHost: workerHost,
		node:       node,
	}
	w.runtimes[rt.id.ToMapKey()] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.id,
	)

	return nil
}

func newWorker(
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
	ias *ias.IAS,
	keyManager *enclaverpc.Client,
	cfg Config,
) (*Worker, error) {
	enabled := false
	if cfg.WorkerBinary != "" || cfg.Backend == host.BackendMock {
		enabled = true
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	w := &Worker{
		enabled:    enabled,
		cfg:        cfg,
		identity:   identity,
		storage:    storage,
		roothash:   roothash,
		registry:   registry,
		epochtime:  epochtime,
		scheduler:  scheduler,
		ias:        ias,
		keyManager: keyManager,
		runtimes:   make(map[signature.MapKey]*Runtime),
		ctx:        ctx,
		cancelCtx:  cancelCtx,
		quitCh:     make(chan struct{}),
		initCh:     make(chan struct{}),
		logger:     logging.GetLogger("worker"),
	}

	if enabled {
		// Create client gRPC server.
		grpc, err := grpc.NewServerEx(cfg.Committee.ClientPort, identity.TLSCertificate)
		if err != nil {
			return nil, err
		}
		w.grpc = grpc
		newClientGRPCServer(grpc.Server(), w)

		// Create P2P node.
		p2p, err := p2p.New(w.ctx, identity, cfg.P2PPort)
		if err != nil {
			return nil, err
		}
		w.p2p = p2p

		// Register all configured runtimes.
		for _, rtCfg := range cfg.Runtimes {
			if err := w.registerRuntime(&cfg, &rtCfg); err != nil {
				return nil, err
			}
		}
	}

	return w, nil
}
