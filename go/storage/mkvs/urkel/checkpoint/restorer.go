package checkpoint

import (
	"context"
	"io"

	db "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
)

// restorer is a checkpoint restorer.
type restorer struct {
	ndb db.NodeDB
}

func (rs *restorer) RestoreChunk(ctx context.Context, chunk *ChunkMetadata, r io.Reader) error {
	return restoreChunk(ctx, rs.ndb, chunk, r)
}

// NewRestorer creates a new checkpoint restorer.
func NewRestorer(ndb db.NodeDB) (Restorer, error) {
	return &restorer{ndb: ndb}, nil
}
