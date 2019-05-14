package compute

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/tracing"
	"github.com/oasislabs/ekiden/go/ias"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/client"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	proxySocketDirName     = "proxy-sockets"
	metricsProxySocketName = "metrics.sock"
	tracingProxySocketName = "tracing.sock"
)

// RuntimeConfig is a single runtime's configuration.
type RuntimeConfig struct {
	ID          signature.PublicKey
	Binary      string
	TEEHardware node.TEEHardware
}

// Config is the compute worker configuration.
type Config struct {
	Backend                   string
	Committee                 committee.Config
	WorkerRuntimeLoaderBinary string
	Runtimes                  []RuntimeConfig
}

// Runtime is a single runtime.
type Runtime struct {
	cfg *RuntimeConfig

	workerHost host.Host
	node       *committee.Node
}

// GetNode returns the committee node for this runtime.
func (r *Runtime) GetNode() *committee.Node {
	if r == nil {
		return nil
	}
	return r.node
}

// Worker is a compute worker handling many runtimes.
type Worker struct {
	enabled bool
	cfg     Config

	commonWorker *workerCommon.Worker
	ias          *ias.IAS
	keyManager   *keymanager.Client
	registration *registration.Registration

	runtimes map[signature.MapKey]*Runtime

	netProxies map[string]NetworkProxy
	socketDir  string

	localStorage *host.LocalStorage

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
		w.logger.Info("not starting compute worker as it is disabled")

		// In case the worker is not enabled, close the init channel immediately.
		close(w.initCh)

		return nil
	}

	// Wait for all runtimes and all proxies to terminate.
	go func() {
		defer close(w.quitCh)
		defer (w.cancelCtx)()

		for _, rt := range w.runtimes {
			<-rt.workerHost.Quit()
			<-rt.node.Quit()
		}

		for _, proxy := range w.netProxies {
			<-proxy.Quit()
		}
	}()

	// Start all the network proxies.
	for _, proxy := range w.netProxies {
		if err := proxy.Start(); err != nil {
			return err
		}
	}

	// Wait for all runtimes to be initialized and for the node
	// to be registered for the current epoch.
	go func() {
		for _, rt := range w.runtimes {
			<-rt.node.Initialized()
		}

		<-w.registration.InitialRegistrationCh()

		close(w.initCh)
	}()

	// Start runtime services.
	for _, rt := range w.runtimes {
		w.logger.Info("starting services for runtime",
			"runtime_id", rt.cfg.ID,
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
			"runtime_id", rt.cfg.ID,
		)

		rt.node.Stop()
		rt.workerHost.Stop()
	}

	for _, proxy := range w.netProxies {
		proxy.Stop()
	}

	if w.localStorage != nil {
		w.localStorage.Stop()
	}
}

// Enabled returns if worker is enabled.
func (w *Worker) Enabled() bool {
	return w.enabled
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

	for _, proxy := range w.netProxies {
		proxy.Cleanup()
	}

	os.RemoveAll(w.socketDir)
}

// Initialized returns a channel that will be closed when the compute worker
// is initialized and ready to service requests.
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
	proxies := make(map[string]host.ProxySpecification)
	for k, v := range w.netProxies {
		proxies[k] = host.ProxySpecification{
			ProxyType:  v.Type(),
			SourceName: v.UnixPath(),
			OuterAddr:  v.RemoteAddress(),
		}
	}
	switch strings.ToLower(cfg.Backend) {
	case host.BackendSandboxed:
		h, err = host.NewSandboxedHost(
			rtCfg.ID.String(),
			cfg.WorkerRuntimeLoaderBinary,
			rtCfg.Binary,
			proxies,
			rtCfg.TEEHardware,
			w.ias,
			newHostHandler(rtCfg.ID, w.commonWorker.Storage, w.keyManager, w.localStorage),
			false,
		)
	case host.BackendUnconfined:
		h, err = host.NewSandboxedHost(
			rtCfg.ID.String(),
			cfg.WorkerRuntimeLoaderBinary,
			rtCfg.Binary,
			proxies,
			rtCfg.TEEHardware,
			w.ias,
			newHostHandler(rtCfg.ID, w.commonWorker.Storage, w.keyManager, w.localStorage),
			true,
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

	// Get other nodes from this runtime.
	commonNode := w.commonWorker.GetRuntime(rtCfg.ID).GetNode()

	// Create worker host for the given runtime.
	workerHost, err := w.newWorkerHost(cfg, rtCfg)
	if err != nil {
		return err
	}

	// Create committee node for the given runtime.
	nodeCfg := cfg.Committee

	node, err := committee.NewNode(
		commonNode,
		workerHost,
		nodeCfg,
	)
	if err != nil {
		return err
	}

	commonNode.AddHooks(node)

	rt := &Runtime{
		cfg:        rtCfg,
		workerHost: workerHost,
		node:       node,
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
	commonWorker *workerCommon.Worker,
	ias *ias.IAS,
	keyManager *keymanager.Client,
	registration *registration.Registration,
	cfg Config,
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
		enabled:      enabled,
		cfg:          cfg,
		commonWorker: commonWorker,
		ias:          ias,
		keyManager:   keyManager,
		registration: registration,
		runtimes:     make(map[signature.MapKey]*Runtime),
		netProxies:   make(map[string]NetworkProxy),
		socketDir:    socketDir,
		ctx:          ctx,
		cancelCtx:    cancelCtx,
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/compute"),
	}

	if enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for compute worker")
		}

		if cfg.WorkerRuntimeLoaderBinary == "" && cfg.Backend != host.BackendMock {
			return nil, fmt.Errorf("compute/worker: no runtime loader binary configured and backend not host.BackendMock")
		}
		if len(cfg.Runtimes) == 0 {
			return nil, fmt.Errorf("compute/worker: no runtimes configured")
		}

		// Create required network proxies.
		metricsConfig := metrics.GetServiceConfig()
		if metricsConfig.Mode == "push" {
			var proxy NetworkProxy
			proxy, err = NewNetworkProxy(host.MetricsProxyKey, "http", filepath.Join(w.socketDir, metricsProxySocketName), metricsConfig.Address)
			if err != nil {
				return nil, err
			}
			w.netProxies[host.MetricsProxyKey] = proxy
		}

		tracingConfig := tracing.GetServiceConfig()
		if tracingConfig.Enabled {
			var (
				address string
				proxy   NetworkProxy
			)

			address, err = common.GetHostPort(tracingConfig.AgentAddress)
			if err != nil {
				return nil, err
			}
			proxy, err = NewNetworkProxy(host.TracingProxyKey, "dgram", filepath.Join(w.socketDir, tracingProxySocketName), address)
			if err != nil {
				return nil, err
			}
			w.netProxies[host.TracingProxyKey] = proxy
		}

		// Open the local storage.
		if w.localStorage, err = host.NewLocalStorage(dataDir, "worker-local-storage.bolt.db"); err != nil {
			return nil, err
		}

		// Register all configured runtimes.
		for _, rtCfg := range cfg.Runtimes {
			if err = w.registerRuntime(&cfg, &rtCfg); err != nil {
				return nil, err
			}
		}

		// Register compute worker role.
		w.registration.RegisterRole(func(n *node.Node) error {
			n.AddRoles(node.RoleComputeWorker)

			for _, rt := range n.Runtimes {
				var err error

				if rt.Capabilities.TEE, err = w.runtimes[rt.ID.ToMapKey()].workerHost.WaitForCapabilityTEE(w.ctx); err != nil {
					w.logger.Error("failed to obtain CapabilityTEE",
						"err", err,
						"runtime", rt.ID,
					)
					continue
				}
			}

			return nil
		})
	}

	startedOk = true
	return w, nil
}
