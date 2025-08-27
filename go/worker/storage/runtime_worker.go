package storage

import (
	"context"
	"fmt"

	"github.com/eapache/channels"
	"golang.org/x/sync/errgroup"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	runtimeAPI "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/availabilitynudger"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/checkpointer"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/statesync"
)

// Worker is handling storage operations for a single runtime.
type worker struct {
	commonNode         *committeeCommon.Node
	logger             *logging.Logger
	stateSync          *statesync.Worker
	checkpointer       *checkpointer.Worker
	availabilityNudger *availabilitynudger.Worker
	stateSyncBlkCh     *channels.InfiniteChannel
	availabilityBlkCh  *channels.InfiniteChannel
}

func newRuntimeWorker(
	commonNode *committeeCommon.Node,
	rp registration.RoleProvider,
	rpRPC registration.RoleProvider,
	localStorage api.LocalBackend,
	checkpointSyncCfg *statesync.CheckpointSyncConfig,
	checkpointerEnabled bool,
) (*worker, error) {
	worker := &worker{
		commonNode:        commonNode,
		logger:            logging.GetLogger("worker/storage").With("runtimeID", commonNode.Runtime.ID()),
		stateSyncBlkCh:    channels.NewInfiniteChannel(),
		availabilityBlkCh: channels.NewInfiniteChannel(),
	}

	stateSync, err := statesync.New(
		commonNode,
		localStorage,
		worker.stateSyncBlkCh,
		checkpointSyncCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create state sync worker: %w", err)
	}
	worker.stateSync = stateSync

	cpCfg := checkpointer.Config{
		CheckpointerEnabled: config.GlobalConfig.Storage.Checkpointer.Enabled,
		CheckInterval:       config.GlobalConfig.Storage.Checkpointer.CheckInterval,
		ParallelChunker:     config.GlobalConfig.Storage.Checkpointer.ParallelChunker,
	}
	checkpointer, err := checkpointer.New(commonNode, localStorage, stateSync, cpCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkpointer worker: %w", err)
	}
	worker.checkpointer = checkpointer

	worker.availabilityNudger = availabilitynudger.New(rp, rpRPC, worker.availabilityBlkCh, stateSync, commonNode.Runtime.ID())

	return worker, nil
}

// NodeHooks implementation.

// HandleNewBlockEarlyLocked is guarded by CrossNode.
func (w *worker) HandleNewBlockEarlyLocked(*runtimeAPI.BlockInfo) {
	// Nothing to do here.
}

// HandleNewBlockLocked is guarded by CrossNode.
func (w *worker) HandleNewBlockLocked(bi *runtimeAPI.BlockInfo) {
	// Notify the state syncer and availability nudger that there is a new block.
	w.stateSyncBlkCh.In() <- bi.RuntimeBlock
	w.availabilityBlkCh.In() <- bi.RuntimeBlock
}

// HandleRuntimeHostEventLocked is guarded by CrossNode.
func (w *worker) HandleRuntimeHostEventLocked(*host.Event) {
	// Nothing to do here.
}

// Initialized returns a channel that will be closed once the worker finished starting up.
func (w *worker) Initialized() <-chan struct{} {
	return w.stateSync.Initialized()
}

func (w *worker) GetStatus(ctx context.Context) (*storageAPI.Status, error) {
	return w.stateSync.GetStatus(ctx)
}

func (w *worker) PauseCheckpointer(pause bool) error {
	return w.checkpointer.PauseCheckpointer(pause)
}

func (w *worker) serve(ctx context.Context) error {
	w.logger.Info("started")
	defer w.logger.Info("stopped")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create runtime checkpoint for every consensus checkpoint, to make it faster for storage nodes
	// that use consensus state sync to catch up as exactly the right checkpoint will be available.
	// Intentionally not part of the errgroup below as failing checkpointer should not stop state sync.
	go func() {
		err := w.checkpointer.Serve(ctx)
		if err != nil {
			w.logger.Info("checkpointer worker failed", "err", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := w.stateSync.Serve(ctx); err != nil {
			return fmt.Errorf("state sync worker failed: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		if err := w.availabilityNudger.Serve(ctx); err != nil {
			return fmt.Errorf("availability nudger failed: %w", err)
		}
		return nil
	})
	return g.Wait()
}
