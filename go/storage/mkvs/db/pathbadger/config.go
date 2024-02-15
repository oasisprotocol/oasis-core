package pathbadger

import (
	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"

	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// commonConfigToBadgerOptions prepares a badger option struct with common options.
func commonConfigToBadgerOptions(cfg *api.Config, logger *logging.Logger) badger.Options {
	opts := badger.DefaultOptions(cfg.DB)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(logger))
	opts = opts.WithSyncWrites(!cfg.NoFsync)
	opts = opts.WithCompression(options.Snappy)
	if cfg.MaxCacheSize == 0 {
		opts = opts.WithBlockCacheSize(64 * 1024 * 1024)
	} else {
		opts = opts.WithBlockCacheSize(cfg.MaxCacheSize)
	}
	opts = opts.WithReadOnly(cfg.ReadOnly)
	opts = opts.WithDetectConflicts(false)

	if cfg.MemoryOnly {
		logger.Warn("using memory-only mode, data will not be persisted")
		opts = opts.WithInMemory(true).WithDir("").WithValueDir("")
	}

	return opts
}
