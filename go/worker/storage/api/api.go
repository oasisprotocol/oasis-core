package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// ModuleName is the storage worker module name.
const ModuleName = "worker/storage"

var (
	// ErrRuntimeNotFound is the error returned when the called references an unknown runtime.
	ErrRuntimeNotFound = errors.New(ModuleName, 1, "worker/storage: runtime not found")
	// ErrCantPauseCheckpointer is the error returned when trying to pause the checkpointer without
	// setting the debug flag.
	ErrCantPauseCheckpointer = errors.New(ModuleName, 2, "worker/storage: pausing checkpointer only available in debug mode")
)

// StorageWorker is the storage worker control API interface.
type StorageWorker interface {
	// GetLastSyncedRound retrieves the last synced round for the storage worker.
	GetLastSyncedRound(ctx context.Context, request *GetLastSyncedRoundRequest) (*GetLastSyncedRoundResponse, error)

	// PauseCheckpointer pauses or unpauses the storage worker's checkpointer.
	PauseCheckpointer(ctx context.Context, request *PauseCheckpointerRequest) error
}

// GetLastSyncedRoundRequest is a GetLastSyncedRound request.
type GetLastSyncedRoundRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
}

// GetLastSyncedRoundResponse is a GetLastSyncedRound response.
type GetLastSyncedRoundResponse struct {
	Round     uint64       `json:"round"`
	IORoot    storage.Root `json:"io_root"`
	StateRoot storage.Root `json:"state_root"`
}

// PauseCheckpointerRequest is a PauseCheckpointer request.
type PauseCheckpointerRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Pause     bool             `json:"pause"`
}

// Status is the storage worker status.
type Status struct {
	// LastFinalizedRound is the last synced and finalized round.
	LastFinalizedRound uint64 `json:"last_finalized_round"`
}
