package statesync

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
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

		p.logger.Debug("pruning storage for round", "round", round)

		// Prune given block.
		err := p.worker.localStorage.NodeDB().Prune(round)
		switch err {
		case nil:
		case mkvsDB.ErrNotEarliest:
			p.logger.Debug("skipping non-earliest round",
				"round", round,
			)
			continue
		default:
			p.logger.Error("failed to prune block",
				"err", err,
			)
			return err
		}
	}

	return nil
}
