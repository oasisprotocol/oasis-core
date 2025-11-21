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

// CanPruneRuntime returns no error when pruning would not go past last synced round.
//
// Implements runtime.history.PruneHandler.
func (p *pruneHandler) CanPruneRuntime(rounds []uint64) error {
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

// statePruner handles pruning of the runtime state.
//
// Everytime pruning is triggered, the pruner removes rounds that are older than the earliest
// round in the runtime’s history.
//
// TODO: Pruning logic is not robust as developer changing the pruning of the runtime history
// may also unexpectedly change the pruning behavior of the state db. This could be fixed
// by making the storage committee worker responsible for both syncing and pruning of the
// history and state DB. See https://github.com/oasisprotocol/oasis-core/issues/6400.
type statePruner struct {
	state    mkvsDB.NodeDB
	history  history.History
	interval time.Duration
	logger   *logging.Logger
}

// newPruner creates new runtime state pruner.
func newPruner(ndb mkvsDB.NodeDB, history history.History, interval time.Duration) *statePruner {
	return &statePruner{
		state:    ndb,
		history:  history,
		interval: max(interval, time.Second),
		logger:   logging.GetLogger("/worker/storage/state-pruner").With("runtime_id", history.RuntimeID()),
	}
}

// serve periodically triggers the pruning of the runtime state db.
func (p *statePruner) serve(ctx context.Context) error {
	p.logger.Info("starting")
	defer p.logger.Info("stopped")

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if err := p.prune(ctx); err != nil {
			p.logger.Warn("failed to prune", "err", err)
		}
	}
}

func (p *statePruner) prune(ctx context.Context) error {
	blk, err := p.history.GetEarliestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get earliest block from runtime history: %w", err)
	}

	for round := p.state.GetEarliestVersion(); round < blk.Header.Round; round++ {
		p.logger.Debug("pruning", "round", round)
		if err := p.state.Prune(round); err != nil {
			return fmt.Errorf("failed to prune round %d: %w", round, err)
		}
	}

	return nil
}
