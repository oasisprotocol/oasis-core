package badger

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/dgraph-io/badger/v3/options"

	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// Timestamp at which database metadata is stored. This needs to be 1 so that we can discard any
// invalid/removed cruft while still keeping everything else even if pruning is not enabled.
const tsMetadata = 1

// versionToTs converts a MKVS version to a Badger timestamp.
func versionToTs(version uint64) uint64 {
	// Version 0 starts at timestamp after metadata.
	return tsMetadata + 1 + version
}

// tsToVersion converts a Badger timestamp to a MKVS version.
func tsToVersion(ts uint64) uint64 {
	if ts < tsMetadata+1 {
		return 0
	}
	return ts - tsMetadata - 1
}

// commonConfigToBadgerOptions prepares a badger option struct with common options.
func commonConfigToBadgerOptions(cfg *api.Config, db *badgerNodeDB) badger.Options {
	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(db.logger))
	opts = opts.WithSyncWrites(!cfg.NoFsync)
	opts = opts.WithCompression(options.Snappy)
	if cfg.MaxCacheSize == 0 {
		// Default to 64mb block cache size if not configured to avoid a panic.
		opts = opts.WithBlockCacheSize(64 * 1024 * 1024)
	} else {
		opts = opts.WithBlockCacheSize(cfg.MaxCacheSize)
	}
	opts = opts.WithReadOnly(cfg.ReadOnly)
	opts = opts.WithDetectConflicts(false)

	if cfg.MemoryOnly {
		db.logger.Warn("using memory-only mode, data will not be persisted")
		opts = opts.WithInMemory(true).WithDir("").WithValueDir("")
	}

	return opts
}
