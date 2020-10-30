package badger

import (
	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"

	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// Timestamp at which database metadata is stored. This needs to be 1 so that we can discard any
// invalid/removed cruft while still keeping everything else even if pruning is not enabled.
const tsMetadata = 1

// versionToTs converts a MKVS version to a badger timestamp.
func versionToTs(version uint64) uint64 {
	// Version 0 starts at timestamp after metadata.
	return tsMetadata + 1 + version
}

// commonConfigToBadgerOptions prepares a badger option struct with common options.
func commonConfigToBadgerOptions(cfg *api.Config, db *badgerNodeDB) badger.Options {
	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(db.logger))
	opts = opts.WithSyncWrites(!cfg.NoFsync)
	// Allow value log truncation if required (this is needed to recover the
	// value log file which can get corrupted in crashes).
	opts = opts.WithTruncate(true)
	opts = opts.WithCompression(options.Snappy)
	opts = opts.WithBlockCacheSize(cfg.MaxCacheSize)
	opts = opts.WithReadOnly(cfg.ReadOnly)
	opts = opts.WithDetectConflicts(false)

	if cfg.MemoryOnly {
		db.logger.Warn("using memory-only mode, data will not be persisted")
		opts = opts.WithInMemory(true).WithDir("").WithValueDir("")
	}

	return opts
}
