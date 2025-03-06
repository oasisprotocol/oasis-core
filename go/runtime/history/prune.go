package history

import (
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	// PrunerStrategyNone is the name of the none pruner strategy.
	PrunerStrategyNone = "none"
	// PrunerStrategyKeepLast is the name of the keep last pruner strategy.
	PrunerStrategyKeepLast = "keep_last"

	// maxBatchSize is the maximum number of rounds to prune in one pass.
	maxBatchSize = 64
)

// PrunerFactory is the runtime history pruner factory interface.
type PrunerFactory func(runtimeID common.Namespace, db *DB) (Pruner, error)

// PruneHandler is a handler that is called when rounds are pruned
// from history.
type PruneHandler interface {
	// Prune is called before the specified rounds are pruned.
	//
	// If an error is returned, pruning is aborted and the rounds are
	// not pruned from history.
	//
	// Note that this can be called for the same round multiple
	// times (e.g., if one of the handlers fails but others succeed
	// and pruning is later retried).
	Prune(rounds []uint64) error
}

// Pruner is the runtime history pruner interface.
type Pruner interface {
	// Prune purges unneeded history, given the latest round.
	Prune(latestRound uint64) error

	// PruneInterval specifies how often pruning should occur.
	PruneInterval() time.Duration

	// RegisterHandler registers a prune handler.
	RegisterHandler(handler PruneHandler)
}

type nonePruner struct{}

// Prune implements Pruner.
func (p *nonePruner) Prune(uint64) error {
	return nil
}

// PruneInterval implements Pruner.
func (p *nonePruner) PruneInterval() time.Duration {
	return time.Hour
}

// RegisterHandler implements Pruner.
func (p *nonePruner) RegisterHandler(PruneHandler) {
}

// NewNonePruner creates a new pruner that never prunes anything.
func NewNonePruner() Pruner {
	return &nonePruner{}
}

// NewNonePrunerFactory creates a new pruner factory for pruners that never
// prune anything.
func NewNonePrunerFactory() PrunerFactory {
	return func(_ common.Namespace, _ *DB) (Pruner, error) {
		return NewNonePruner(), nil
	}
}

type keepLastPruner struct {
	logger *logging.Logger
	db     *DB

	numKept       uint64
	pruneInterval time.Duration

	mu       sync.RWMutex
	handlers []PruneHandler
}

// Prune implements Pruner.
func (p *keepLastPruner) Prune(latestRound uint64) error {
	if latestRound < p.numKept {
		return nil
	}

	lastPrunedRound := latestRound - p.numKept

	return p.db.db.Update(func(tx *badger.Txn) error {
		// NOTE: Do not prefetch values as we are only looking at keys.
		it := tx.NewIterator(badger.IteratorOptions{
			Prefix: blockKeyFmt.Encode(),
		})
		defer it.Close()

		// Start with the smallest round and proceed forward.
		var pruned []uint64
		for it.Rewind(); it.Valid() && len(pruned) < maxBatchSize; it.Next() {
			item := it.Item()

			var round uint64
			if !blockKeyFmt.Decode(item.Key(), &round) {
				// This should not happen as the Badger iterator should take care of it.
				panic("runtime/history: bad iterator")
			}

			if round > lastPrunedRound {
				break
			}

			if err := tx.Delete(item.KeyCopy(nil)); err != nil {
				if err == badger.ErrTxnTooBig {
					// We can't prune any more rounds in this transaction.
					break
				}
				return err
			}

			pruned = append(pruned, round)
		}

		// If there is nothing to prune, do not call any handlers.
		if len(pruned) == 0 {
			return nil
		}

		// Before pruning anything, run all prune handlers. If any of them
		// fails we abort the prune.
		p.mu.RLock()
		defer p.mu.RUnlock()

		for _, ph := range p.handlers {
			if err := ph.Prune(pruned); err != nil {
				p.logger.Error("prune handler failed, aborting prune",
					"err", err,
					"round_count", len(pruned),
					"round_min", pruned[0],
					"round_max", pruned[len(pruned)-1],
				)
				return fmt.Errorf("runtime/history: prune handler failed: %w", err)
			}
		}

		return nil
	})
}

// PruneInterval implements Pruner.
func (p *keepLastPruner) PruneInterval() time.Duration {
	return p.pruneInterval
}

func (p *keepLastPruner) RegisterHandler(handler PruneHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.handlers = append(p.handlers, handler)
}

// NewKeepLastPruner creates a pruner that keeps the last configured
// number of rounds.
func NewKeepLastPruner(runtimeID common.Namespace, numKept uint64, pruneInterval time.Duration, db *DB) (Pruner, error) {
	return &keepLastPruner{
		logger:        logging.GetLogger("runtime/prune/keep_last").With("runtime_id", runtimeID),
		db:            db,
		numKept:       numKept,
		pruneInterval: pruneInterval,
		handlers:      make([]PruneHandler, 0),
	}, nil
}

// NewKeepLastPrunerFactory creates a new pruner factory for pruners that keep
// the last configured number of rounds.
func NewKeepLastPrunerFactory(numKept uint64, pruneInterval time.Duration) PrunerFactory {
	return func(runtimeID common.Namespace, db *DB) (Pruner, error) {
		return NewKeepLastPruner(runtimeID, numKept, pruneInterval, db)
	}
}
