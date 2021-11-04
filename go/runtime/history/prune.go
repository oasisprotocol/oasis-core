package history

import (
	"context"
	"fmt"
	"sync"

	"github.com/dgraph-io/badger/v3"

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
type PrunerFactory func(db *DB) (Pruner, error)

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
	Prune(ctx context.Context, rounds []uint64) error
}

// Pruner is the runtime history pruner interface.
type Pruner interface {
	// Prune purges unneeded history, given the latest round.
	Prune(ctx context.Context, latestRound uint64) error

	// RegisterHandler registers a prune handler.
	RegisterHandler(handler PruneHandler)
}

type prunerBase struct {
	sync.RWMutex

	handlers []PruneHandler
}

func (p *prunerBase) RegisterHandler(handler PruneHandler) {
	p.Lock()
	defer p.Unlock()

	p.handlers = append(p.handlers, handler)
}

func newPrunerBase() prunerBase {
	return prunerBase{}
}

type nonePruner struct{}

func (p *nonePruner) RegisterHandler(handler PruneHandler) {
}

func (p *nonePruner) Prune(ctx context.Context, latestRound uint64) error {
	return nil
}

// NewNonePruner creates a new pruner that never prunes anything.
func NewNonePruner() PrunerFactory {
	return func(db *DB) (Pruner, error) {
		return &nonePruner{}, nil
	}
}

type keepLastPruner struct {
	prunerBase

	logger *logging.Logger
	db     *DB

	numKept uint64
}

func (p *keepLastPruner) Prune(ctx context.Context, latestRound uint64) error {
	if latestRound < p.numKept {
		return nil
	}

	p.prunerBase.RLock()
	defer p.prunerBase.RUnlock()

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

			if err := tx.Delete(roundResultsKeyFmt.Encode(round)); err != nil {
				if err == badger.ErrTxnTooBig {
					// We can't prune any more rounds in this transaction.
					break
				}
				return err
			}

			if err := tx.Delete(item.KeyCopy(nil)); err != nil {
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
		for _, ph := range p.prunerBase.handlers {
			if err := ph.Prune(ctx, pruned); err != nil {
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

// NewKeepLastPruner creates a pruner that keeps the last configured
// number of rounds.
func NewKeepLastPruner(numKept uint64) PrunerFactory {
	return func(db *DB) (Pruner, error) {
		return &keepLastPruner{
			prunerBase: newPrunerBase(),
			logger:     logging.GetLogger("history/prune/keep_last"),
			db:         db,
			numKept:    numKept,
		}, nil
	}
}
