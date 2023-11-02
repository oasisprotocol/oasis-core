//go:build !rocksdb

package rocksdb

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// New creates a new RocksDB-backed node database.
func New(cfg *api.Config) (api.NodeDB, error) {
	return nil, fmt.Errorf("mkvs/rocksdb: not compiled with RocksDB support")
}
