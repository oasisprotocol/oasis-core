package storage

import (
	"context"
	"fmt"

	"github.com/eapache/channels"
	"golang.org/x/sync/errgroup"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	runtimeAPI "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	storageAPI "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/statesync"
)

// Worker is handling storage operations for a single runtime.
type worker struct {
	logger         *logging.Logger
	stateSync      *statesync.Worker
	stateSyncBlkCh *channels.InfiniteChannel
}

func newRuntimeWorker(
	commonNode *committeeCommon.Node,
	rp registration.RoleProvider,
	rpRPC registration.RoleProvider,
	localStorage api.LocalBackend,
	checkpointerCfg *statesync.CheckpointSyncConfig,
) (*worker, error) {
	worker := &worker{
		logger:         logging.GetLogger("worker/storage").With("runtimeID", commonNode.Runtime.ID()),
		stateSyncBlkCh: channels.NewInfiniteChannel(),
	}

	stateSync, err := statesync.New(
		commonNode,
		rp,
		rpRPC,
		localStorage,
		worker.stateSyncBlkCh,
		checkpointerCfg,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create state sync worker: %w", err)
	}

	worker.stateSync = stateSync

	return worker, nil
}

// NodeHooks implementation.

// HandleNewBlockEarlyLocked is guarded by CrossNode.
func (w *worker) HandleNewBlockEarlyLocked(*runtimeAPI.BlockInfo) {
	// Nothing to do here.
}

// HandleNewBlockLocked is guarded by CrossNode.
func (w *worker) HandleNewBlockLocked(bi *runtimeAPI.BlockInfo) {
	// Notify the state syncer that there is a new block.
	w.stateSyncBlkCh.In() <- bi.RuntimeBlock
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
	return w.stateSync.PauseCheckpointer(pause)
}

func (w *worker) serve(ctx context.Context) error {
	w.logger.Info("started")
	defer w.logger.Info("stopped")

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return w.stateSync.Serve(ctx)
	})
	return g.Wait()
}
