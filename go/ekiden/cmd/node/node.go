// Package node implements the ekiden node.
package node

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/beacon"
	beaconAPI "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/dummydebug"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/pprof"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/tracing"
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
	"github.com/oasislabs/ekiden/go/worker"
)

// Run runs the ekiden node.
func Run(cmd *cobra.Command, args []string) {
	// Re-register flags due to https://github.com/spf13/viper/issues/233.
	RegisterFlags(cmd)

	node, err := NewNode()
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
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
	svcTmnt service.TendermintService

	Identity  *identity.Identity
	Beacon    beaconAPI.Backend
	Epochtime epochtimeAPI.Backend
	Registry  registryAPI.Backend
	RootHash  roothashAPI.Backend
	Scheduler schedulerAPI.Backend
	Storage   storageAPI.Backend
	Worker    *worker.Worker
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
	dataDir := cmdCommon.DataDir()

	var err error

	// Initialize the various backends.
	if n.Epochtime, err = epochtime.New(n.svcTmnt); err != nil {
		return err
	}
	if n.Beacon, err = beacon.New(n.Epochtime, n.svcTmnt); err != nil {
		return err
	}
	if n.Registry, err = registry.New(n.Epochtime, n.svcTmnt); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Registry, "registry backend")
	if n.Scheduler, err = scheduler.New(n.Epochtime, n.Registry, n.Beacon, n.svcTmnt); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Scheduler, "scheduler backend")
	if n.Storage, err = storage.New(n.Epochtime, dataDir); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.Storage, "storage backend")
	if n.RootHash, err = roothash.New(n.Epochtime, n.Scheduler, n.Storage, n.Registry, n.svcTmnt); err != nil {
		return err
	}
	n.svcMgr.RegisterCleanupOnly(n.RootHash, "roothash backend")

	// Initialize and register the gRPC services.
	grpcSrv := n.grpcSrv.Server()
	epochtime.NewGRPCServer(grpcSrv, n.Epochtime)
	beacon.NewGRPCServer(grpcSrv, n.Beacon)
	registry.NewGRPCServer(grpcSrv, n.Registry)
	roothash.NewGRPCServer(grpcSrv, n.RootHash)
	scheduler.NewGRPCServer(grpcSrv, n.Scheduler)
	storage.NewGRPCServer(grpcSrv, n.Storage)
	dummydebug.NewGRPCServer(grpcSrv, n.Epochtime, n.Registry)

	cmdCommon.Logger().Debug("backends initialized")

	return nil
}

// NewNode initializes and launches the ekiden node service.
//
// WARNING: This will misbehave iff cmd != RootCommand().  This is exposed
// for the benefit of tests and the interface is not guaranteed to be stable.
func NewNode() (*Node, error) {
	logger := cmdCommon.Logger()

	node := &Node{
		svcMgr: background.NewServiceManager(logger),
	}

	var startOk bool
	defer func() {
		if !startOk {
			node.Cleanup()
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		return nil, err
	}

	logger.Info("starting ekiden node")

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory not configured")
		return nil, errors.New("data directory not configured")
	}

	var err error

	// Generate/Load the node identity.
	node.Identity, err = identity.LoadOrGenerate(dataDir)
	if err != nil {
		logger.Error("failed to load/generate identity",
			"err", err,
		)
		return nil, err
	}

	logger.Info("loaded/generated node identity",
		"public_key", node.Identity.NodeKey.Public(),
	)

	// Initialize the tracing client.
	tracingSvc, err := tracing.New("ekiden-node")
	if err != nil {
		logger.Error("failed to initialize tracing",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.RegisterCleanupOnly(tracingSvc, "tracing")

	// Initialize the gRPC server.
	// Depends on global tracer.
	node.grpcSrv, err = grpc.NewServer()
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New()
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New()
	if err != nil {
		logger.Error("failed to initialize pprof server",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		logger.Error("failed to start pprof server",
			"err", err,
		)
		return nil, err
	}

	// Initialize tendermint.
	node.svcTmnt = tendermint.New(dataDir, node.Identity)
	node.svcMgr.Register(node.svcTmnt)

	// Initialize the varous node backends.
	if err = node.initBackends(); err != nil {
		logger.Error("failed to initialize backends",
			"err", err,
		)
		return nil, err
	}

	// Initialize the worker.
	node.Worker, err = worker.New(
		node.Identity,
		node.Storage,
		node.RootHash,
		node.Registry,
		node.Epochtime,
		node.Scheduler,
	)
	if err != nil {
		logger.Error("failed to initialize compute worker",
			"err", err,
		)
		return nil, err
	}
	node.svcMgr.Register(node.Worker)

	// Start metric server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metric server",
			"err", err,
		)
		return nil, err
	}

	// Start the tendermint service.
	//
	// Note: This will only start the node if it is required by
	// one of the backends.
	if err = node.svcTmnt.Start(); err != nil {
		logger.Error("failed to start tendermint service",
			"err", err,
		)
		return nil, err
	}

	// Start the gRPC server.
	if err = node.grpcSrv.Start(); err != nil {
		logger.Error("failed to start gRPC server",
			"err", err,
		)
		return nil, err
	}

	// Start the worker.
	if err = node.Worker.Start(); err != nil {
		logger.Error("failed to start worker",
			"err", err,
		)
		return nil, err
	}

	logger.Info("initialization complete: ready to serve")
	startOk = true

	return node, nil
}

// RegisterFlags registers the flags used by the node command.
func RegisterFlags(cmd *cobra.Command) {
	// Backend initialization flags.
	for _, v := range []func(*cobra.Command){
		metrics.RegisterFlags,
		tracing.RegisterFlags,
		grpc.RegisterServerFlags,
		pprof.RegisterFlags,
		beacon.RegisterFlags,
		epochtime.RegisterFlags,
		registry.RegisterFlags,
		roothash.RegisterFlags,
		scheduler.RegisterFlags,
		storage.RegisterFlags,
		tendermint.RegisterFlags,
		worker.RegisterFlags,
	} {
		v(cmd)
	}
}
