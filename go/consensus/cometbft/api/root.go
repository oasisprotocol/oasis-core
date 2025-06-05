package api

import (
	"context"

	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// StateRooter provides access to state roots.
type StateRooter interface {
	// StateRoot returns the state root at the given block height.
	StateRoot(ctx context.Context, height int64) (mkvsNode.Root, error)
}
