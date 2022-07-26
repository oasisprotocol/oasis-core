package storage

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

var _ api.StorageWorker = (*Worker)(nil)

func (w *Worker) GetLastSyncedRound(ctx context.Context, request *api.GetLastSyncedRoundRequest) (*api.GetLastSyncedRoundResponse, error) {
	node := w.runtimes[request.RuntimeID]
	if node == nil {
		return nil, api.ErrRuntimeNotFound
	}

	round, ioRoot, stateRoot := node.GetLastSynced()
	return &api.GetLastSyncedRoundResponse{
		Round:     round,
		IORoot:    ioRoot,
		StateRoot: stateRoot,
	}, nil
}

func (w *Worker) PauseCheckpointer(ctx context.Context, request *api.PauseCheckpointerRequest) error {
	node := w.runtimes[request.RuntimeID]
	if node == nil {
		return api.ErrRuntimeNotFound
	}

	return node.PauseCheckpointer(request.Pause)
}
