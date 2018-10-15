// Package cmd implements the commands for the ekiden executable.
package cmd

import (
	"crypto/rand"
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon"
	beaconAPI "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/dummydebug"
	"github.com/oasislabs/ekiden/go/epochtime"
	epochtimeAPI "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry"
	registryAPI "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash"
	roothashAPI "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/scheduler"
	schedulerAPI "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage"
	storageAPI "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgDataDir  = "datadir"
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"
)

var (
	// Common config flags.
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

	rootCmd = &cobra.Command{
		Use:     "ekiden",
		Short:   "Ekiden",
		Version: "0.2.0-alpha",
		Run:     nodeMain,
	}

	rootLog = logging.GetLogger("ekiden")
)

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logAndExit(err)
	}
}

// RootCommand returns the root (top level) cobra.Command.
func RootCommand() *cobra.Command {
	return rootCmd
}

func nodeMain(cmd *cobra.Command, args []string) {
	node, err := NewNode(cmd)
	if err != nil {
		return
	}
	defer node.Cleanup()

	node.Wait()
}

// Node is the ekiden node service.
//
// WARNING: This is exposed for the benefit of tests and the interface
// is not guaranteed to be stable.
type Node struct {
	cmd      *cobra.Command
	svcMgr   *backgroundServiceManager
	identity *signature.PrivateKey
	grpcSrv  *grpcService
	svcTmnt  service.TendermintService

	Beacon    beaconAPI.Backend
	Epochtime epochtimeAPI.Backend
	Registry  registryAPI.Backend
	RootHash  roothashAPI.Backend
	Scheduler schedulerAPI.Backend
	Storage   storageAPI.Backend
}

// Cleanup cleans up after the ndoe has terminated.
func (n *Node) Cleanup() {
	n.svcMgr.Cleanup()
}

// Stop gracefully terminates the node.
func (n *Node) Stop() {
	n.svcMgr.Stop()
}

// Wait waits for the node to gracefully terminate.  Callers MUST
// call Cleanup() after wait returns.
func (n *Node) Wait() {
	n.svcMgr.Wait()
}

func (n *Node) initBackends() error {
	var err error

	// Initialize the various backends.
	if n.Epochtime, err = epochtime.New(n.cmd, n.svcTmnt); err != nil {
		return err
	}
	if n.Beacon, err = beacon.New(n.cmd, n.Epochtime, n.svcTmnt); err != nil {
		return err
	}
	if n.Registry, err = registry.New(n.cmd, n.Epochtime, n.svcTmnt); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Registry)
	if n.Scheduler, err = scheduler.New(n.cmd, n.Epochtime, n.Registry, n.Beacon); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Scheduler)
	if n.Storage, err = storage.New(n.cmd, n.Epochtime, dataDir); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Storage)
	if n.RootHash, err = roothash.New(n.cmd, n.Epochtime, n.Scheduler, n.Storage, n.Registry, n.svcTmnt); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.RootHash)

	// Initialize and register the gRPC services.
	epochtime.NewGRPCServer(n.grpcSrv.s, n.Epochtime)
	beacon.NewGRPCServer(n.grpcSrv.s, n.Beacon)
	registry.NewGRPCServer(n.grpcSrv.s, n.Registry)
	roothash.NewGRPCServer(n.grpcSrv.s, n.RootHash)
	scheduler.NewGRPCServer(n.grpcSrv.s, n.Scheduler)
	storage.NewGRPCServer(n.grpcSrv.s, n.Storage)
	dummydebug.NewGRPCServer(n.grpcSrv.s, n.Epochtime, n.Registry)

	rootLog.Debug("backends initialized")

	return nil
}

// NewNode initializes and launches the ekiden node service.
//
// WARNING: This will misbehave iff cmd != RootCommand().  This is exposed
// for the benefit of tests and the interface is not guaranteed to be stable.
func NewNode(cmd *cobra.Command) (*Node, error) {
	node := &Node{
		cmd:    cmd,
		svcMgr: newBackgroundServiceManager(),
	}

	var startOk bool
	defer func() {
		if !startOk {
			node.Cleanup()
		}
	}()

	initCommon()

	rootLog.Info("starting ekiden node")

	if dataDir == "" {
		rootLog.Error("data directory not configured")
		return nil, errors.New("data directory not configured")
	}

	var err error

	// Generate/Load the node identity.
	node.identity, err = initIdentity(dataDir)
	if err != nil {
		rootLog.Error("failed to load/generate identity",
			"err", err,
		)
		return nil, err
	}

	// Initialize the tracing client.
	tracingSvc, err := initTracing(node.cmd, "ekiden-node")
	if err != nil {
		rootLog.Error("failed to initialize tracing",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.RegisterCleanupOnly(tracingSvc)

	// Initialize the gRPC server.
	// Depends on global tracer.
	node.grpcSrv, err = newGrpcService(node.cmd)
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.grpcSrv)

	// Initialize the metrics server.
	metrics, err := newMetrics(node.cmd)
	if err != nil {
		rootLog.Error("failed to initialize metrics server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := newPprofService(node.cmd)
	if err != nil {
		rootLog.Error("failed to initialize pprof server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		rootLog.Error("failed to start pprof server",
			"err", err,
		)
		return nil, err
	}

	// Initialize tendermint.
	node.svcTmnt = tendermint.New(node.cmd, dataDir, node.identity)
	node.svcMgr.Register(node.svcTmnt)

	// Initialize the varous node backends.
	if err = node.initBackends(); err != nil {
		rootLog.Error("failed to initialize backends",
			"err", err,
		)
		return nil, err
	}

	// Start metric server.
	if err = metrics.Start(); err != nil {
		rootLog.Error("failed to start metric server",
			"err", err,
		)
		return nil, err
	}

	// Start the tendermint service.
	//
	// Note: This will only start the node if it is required by
	// one of the backends.
	if err = node.svcTmnt.Start(); err != nil {
		rootLog.Error("failed to start tendermint service",
			"err", err,
		)
		return nil, err
	}

	// Start the gRPC server.
	if err = node.grpcSrv.Start(); err != nil {
		rootLog.Error("failed to start gRPC server",
			"err", err,
		)
		return nil, err
	}

	rootLog.Info("initialization complete: ready to serve")
	startOk = true

	return node, nil
}

func initIdentity(dataDir string) (*signature.PrivateKey, error) {
	var k signature.PrivateKey

	if err := k.LoadPEM(filepath.Join(dataDir, "identity.pem"), rand.Reader); err != nil {
		return nil, err
	}

	rootLog.Info("loaded/generated node identity",
		"public_key", k.Public(),
	)

	return &k, nil
}

// nolint: errcheck
func init() {
	cobra.OnInitialize(InitConfig)

	// Global flags common across all commands.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVar(&dataDir, cfgDataDir, "", "data directory")
	rootCmd.PersistentFlags().StringVar(&logFile, cfgLogFile, "", "log file")
	rootCmd.PersistentFlags().StringVar(&logFmt, cfgLogFmt, "Logfmt", "log format")
	rootCmd.PersistentFlags().StringVar(&logLevel, cfgLogLevel, "INFO", "log level")

	for _, v := range []string{
		cfgDataDir,
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
	} {
		viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		registerMetricsFlags,
		registerTracingFlags,
		registerGrpcFlags,
		registerPprofFlags,
		beacon.RegisterFlags,
		epochtime.RegisterFlags,
		registry.RegisterFlags,
		roothash.RegisterFlags,
		scheduler.RegisterFlags,
		storage.RegisterFlags,
		tendermint.RegisterFlags,
	} {
		v(rootCmd)
	}
}
