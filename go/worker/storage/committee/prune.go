package committee

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	mkvsDB "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

type pruneHandler struct {
	logger *logging.Logger
	worker *Worker
}

func (p *pruneHandler) Prune(rounds []uint64) error {
	// Make sure we never prune past what was synced.
	lastSycnedRound, _, _ := p.worker.GetLastSynced()

	for _, round := range rounds {
		if round >= lastSycnedRound {
			return fmt.Errorf("worker/storage: tried to prune past last synced round (last synced: %d)",
				lastSycnedRound,
			)
		}

		// Old suggestion: Make sure we don't prune rounds that need to be checkpointed but haven't been yet.
	}

	return nil
}

// statePruner is responsible for pruning of the runtime state
//
// Everytime pruning is triggered, the pruner checks for the earliest height
// in the runtime light history and removes any older versions stored in the state db.
//
// TOD: This is not the most robust solution as developer changing the pruning of the
// runtime light history may also unexpectedly change the pruning behaviour of the state db.
type statePruner struct {
	state        mkvsDB.NodeDB
	lightHistory history.History
	interval     time.Duration
	logger       *logging.Logger
}

// newPruner creates new runtime state pruner.
func newPruner(ndb mkvsDB.NodeDB, history history.History, interval time.Duration) *statePruner {
	return &statePruner{
		state:        ndb,
		lightHistory: history,
		interval:     interval,
		logger:       logging.GetLogger("/worker/storage/committee/state-pruner").With("runtime_ID", history.RuntimeID()),
	}
}

// serve periodically triggers the pruning of the runtime state db.
func (sp *statePruner) serve(ctx context.Context) error {
	sp.logger.Info("starting")
	defer sp.logger.Info("stopped")

	ticker := time.NewTicker(sp.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := sp.prune(ctx); err != nil {
				sp.logger.Warn("failed to prune", "err", err)
			}
		}
	}
}

func (sp *statePruner) prune(ctx context.Context) error {
	blk, err := sp.lightHistory.GetEarliestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get earliest block from runtime light history: %w", err)
	}

	earliest := sp.state.GetEarliestVersion()

	for v := earliest; v < blk.Header.Round; v++ {
		sp.logger.Debug("pruning storage for version", "version", v)
		err := sp.state.Prune(v)
		switch err {
		case nil:
		case mkvsDB.ErrNotEarliest:
			sp.logger.Debug("skipping non-earliest version",
				"version", v,
			)
			continue
		default:
			return fmt.Errorf("failed to prune version %d: %w", v, err)
		}
	}

	return nil
}
