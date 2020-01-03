package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/errors"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

// ModuleName is the storage worker module name.
const ModuleName = "worker/storage"

// ErrRuntimeNotFound is the error returned when the called references an unknown runtime.
var ErrRuntimeNotFound = errors.New(ModuleName, 1, "worker/storage: runtime not found")

// StorageWorker is the storage worker control API interface.
type StorageWorker interface {
	// GetLastSyncedRound retrieves the last synced round for the storage worker.
	GetLastSyncedRound(ctx context.Context, request *GetLastSyncedRoundRequest) (*GetLastSyncedRoundResponse, error)

	// ForceFinalize forces finalization of a specific round.
	ForceFinalize(ctx context.Context, request *ForceFinalizeRequest) error
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

// ForceFinalizeRequest is a ForceFinalize request.
type ForceFinalizeRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Round     uint64           `json:"round"`
}
