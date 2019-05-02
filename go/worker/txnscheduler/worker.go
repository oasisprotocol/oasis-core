package txnscheduler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/keymanager"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/compute"
	"github.com/oasislabs/ekiden/go/worker/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/committee"
)

const (
	proxySocketDirName = "proxy-sockets"
)

// RuntimeConfig is a single runtime's configuration.
type RuntimeConfig struct {
	ID signature.PublicKey
}

// Config is the transaction scheduler configuration.
type Config struct {
	Backend   string
	Committee committee.Config
	Runtimes  []RuntimeConfig
}

// Runtime is a single runtime.
type Runtime struct {
	cfg *RuntimeConfig

	node *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	return r.node
}

// Worker is a transaction scheduler handling many runtimes.
type Worker struct {
	enabled         bool
	cfg             Config
	workerCommonCfg *workerCommon.Config

	identity     *identity.Identity
	storage      storage.Backend
	roothash     roothash.Backend
	registry     registry.Backend
	epochtime    epochtime.Backend
	scheduler    scheduler.Backend
	syncable     common.Syncable
	keyManager   *keymanager.KeyManager
	compute      *compute.Worker
	p2p          *p2p.P2P
	grpc         *grpc.Server
	registration *registration.Registration

	runtimes map[signature.MapKey]*Runtime

	socketDir string

	ctx       context.Context
	cancelCtx context.CancelFunc
	quitCh    chan struct{}
	initCh    chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "txnscheduler worker"
}

// Start starts the service.
func (w *Worker) Start() error {
	if !w.enabled {
		w.logger.Info("not starting worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for the gRPC server, all runtimes and all proxies to terminate.
	go func() {
		defer close(w.quitCh)
		defer (w.cancelCtx)()

		for _, rt := range w.runtimes {
			<-rt.node.Quit()
		}

		<-w.grpc.Quit()
	}()

	// Wait for all runtimes to be initialized and for the node
	// to be registered for the current epoch.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

		<-w.registration.InitialRegistrationCh()

		close(w.initCh)
	}()

	// Start client gRPC server.
	if err := w.grpc.Start(); err != nil {
		return err
	}

	// Start runtime services.
	for _, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", rt.cfg.ID,
		)

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
			"runtime_id", rt.cfg.ID,
		)

		rt.node.Stop()
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
	}

	w.grpc.Cleanup()

	os.RemoveAll(w.socketDir)
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

func (w *Worker) registerRuntime(cfg *Config, rtCfg *RuntimeConfig) error {
	w.logger.Info("registering new runtime",
		"runtime_id", rtCfg.ID,
	)

	// Get compute committee node for the given runtime.
	computeNode := w.compute.GetRuntime(rtCfg.ID).GetNode()

	// Create committee node for the given runtime.
	nodeCfg := cfg.Committee

	node, err := committee.NewNode(
		rtCfg.ID,
		w.identity,
		w.storage,
		w.roothash,
		w.registry,
		w.epochtime,
		w.scheduler,
		w.syncable,
		computeNode,
		w.p2p,
		nodeCfg,
	)
	if err != nil {
		return err
	}

	rt := &Runtime{
		cfg:  rtCfg,
		node: node,
	}
	w.runtimes[rt.cfg.ID.ToMapKey()] = rt

	w.logger.Info("new runtime registered",
		"runtime_id", rt.cfg.ID,
	)

	return nil
}

func newWorker(
	dataDir string,
	enabled bool,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registryInst registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
	syncable common.Syncable,
	compute *compute.Worker,
	p2p *p2p.P2P,
	registration *registration.Registration,
	keyManager *keymanager.KeyManager,
	cfg Config,
	workerCommonCfg *workerCommon.Config,
) (*Worker, error) {
	startedOk := false
	socketDir := filepath.Join(dataDir, proxySocketDirName)
	err := common.Mkdir(socketDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !startedOk {
			os.RemoveAll(socketDir)
		}
	}()

	ctx, cancelCtx := context.WithCancel(context.Background())

	w := &Worker{
		enabled:         enabled,
		cfg:             cfg,
		workerCommonCfg: workerCommonCfg,
		identity:        identity,
		storage:         storage,
		roothash:        roothash,
		registry:        registryInst,
		epochtime:       epochtime,
		scheduler:       scheduler,
		syncable:        syncable,
		compute:         compute,
		p2p:             p2p,
		registration:    registration,
		keyManager:      keyManager,
		runtimes:        make(map[signature.MapKey]*Runtime),
		socketDir:       socketDir,
		ctx:             ctx,
		cancelCtx:       cancelCtx,
		quitCh:          make(chan struct{}),
		initCh:          make(chan struct{}),
		logger:          logging.GetLogger("worker/txnscheduler"),
	}

	if enabled {
		if len(cfg.Runtimes) == 0 {
			return nil, fmt.Errorf("txnscheduler/worker: no runtimes configured")
		}

		// Create client gRPC server.
		grpc, err := grpc.NewServerTCP("worker-client", workerCommonCfg.ClientPort, identity.TLSCertificate)
		if err != nil {
			return nil, err
		}
		w.grpc = grpc
		newClientGRPCServer(grpc.Server(), w)

		// Register all configured runtimes.
		for _, rtCfg := range cfg.Runtimes {
			if err = w.registerRuntime(&cfg, &rtCfg); err != nil {
				return nil, err
			}
		}

		// Register transaction scheduler worker role.
		w.registration.RegisterRole(func(n *node.Node) error {
			n.AddRoles(node.RoleTransactionScheduler)

			return nil
		})
	}

	startedOk = true
	return w, nil
}
