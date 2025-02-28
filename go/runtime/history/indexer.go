package history

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const batchSize = 1000

// BlockIndexer is responsible for indexing and committing finalized
// runtime blocks from the consensus into the runtime history.
type BlockIndexer struct {
	startOne cmSync.One

	consensus consensus.Backend
	history   History

	logger *logging.Logger
}

// NewBlockIndexer creates a new block indexer.
func NewBlockIndexer(consensus consensus.Backend, history History) *BlockIndexer {
	logger := logging.GetLogger("runtime/history/indexer").With("runtime_id", history.RuntimeID())

	return &BlockIndexer{
		startOne:  cmSync.NewOne(),
		consensus: consensus,
		history:   history,
		logger:    logger,
	}
}

// Start starts the indexer.
func (bi *BlockIndexer) Start() {
	bi.startOne.TryStart(bi.run)
}

// Stop halts the indexer.
func (bi *BlockIndexer) Stop() {
	bi.startOne.TryStop()
}

func (bi *BlockIndexer) run(ctx context.Context) {
	// Subscribe to new runtime blocks.
	blkCh, blkSub, err := bi.consensus.RootHash().WatchBlocks(ctx, bi.history.RuntimeID())
	if err != nil {
		bi.logger.Error("failed to watch blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	// Start a goroutine to handle reindex requests.
	reindexCh := make(chan int64, 1)
	reindexDoneCh := make(chan int64, 1)

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case height, ok := <-reindexCh:
				// Stop once reindex catches up.
				if !ok {
					return
				}
				// Reindex blocks up to the specified height.
				if err := bi.reindex(ctx, height); err != nil {
					bi.logger.Error("failed to reindex blocks",
						"err", err,
						"height", height,
					)
					continue
				}
				// Notify that reindex has been completed.
				sendToChannel(reindexDoneCh, height)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Reindex blocks up to the latest block.
	var blk *roothash.AnnotatedBlock
reindex:
	for {
		select {
		case blk = <-blkCh:
			// Send a new request with the latest height.
			sendToChannel(reindexCh, blk.Height-1)
		case height := <-reindexDoneCh:
			// Stop once reindex catches up.
			if height == blk.Height-1 {
				close(reindexCh)
				break reindex
			}
		case <-ctx.Done():
			return
		}
	}

	// Handle new blocks after reindex is complete.
	for {
		if err = bi.commitBlock(ctx, blk, true); err != nil {
			return
		}

		select {
		case blk = <-blkCh:
		case <-ctx.Done():
			return
		}
	}
}

func (bi *BlockIndexer) reindex(ctx context.Context, height int64) error {
	bi.logger.Debug("reindexing", "height", height)

	lastHeight, err := bi.history.LastConsensusHeight()
	if err != nil {
		bi.logger.Error("failed to get last indexed height",
			"err", err,
		)
		return fmt.Errorf("failed to get last indexed height: %w", err)
	}
	lastHeight++ // +1 since we want the last non-seen height.

	lastRetainedHeight, err := bi.consensus.GetLastRetainedHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last retained height: %w", err)
	}

	if lastHeight < lastRetainedHeight {
		bi.logger.Debug("skipping pruned heights",
			"last_retained_height", lastRetainedHeight,
			"last_height", lastHeight,
		)
		lastHeight = lastRetainedHeight
	}

	for start := lastHeight; start <= height; start += batchSize {
		end := min(start+batchSize-1, height)
		if err = bi.reindexBlocks(ctx, start, end); err != nil {
			return fmt.Errorf("failed to reindex batch: %w", err)
		}
	}

	bi.logger.Debug("reindex completed")
	return nil
}

func (bi *BlockIndexer) reindexBlocks(ctx context.Context, start int64, end int64) error {
	bi.logger.Debug("reindexing blocks",
		"start_height", start,
		"end_height", end,
		logging.LogEvent, roothash.LogEventHistoryReindexing,
	)

	var blocks []*roothash.AnnotatedBlock
	for height := start; height <= end; height++ {
		state, err := bi.consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
			RuntimeID: bi.history.RuntimeID(),
			Height:    height,
		})
		switch {
		case err == nil:
		case errors.Is(err, consensus.ErrVersionNotFound):
			bi.logger.Debug("failed to get runtime state, probably pruned",
				"err", err,
				"height", height,
			)
			continue
		case errors.Is(err, roothash.ErrInvalidRuntime):
			bi.logger.Debug("failed to get runtime state, probably no state yet",
				"err", err,
				"height", height,
			)
			continue
		default:
			bi.logger.Error("failed to get runtime state",
				"err", err,
				"height", height,
			)
			return fmt.Errorf("failed to get runtime state: %w", err)
		}
		if state.LastBlockHeight != height {
			// No new block at this height, skipping.
			continue
		}

		blk := &roothash.AnnotatedBlock{
			Height: state.LastBlockHeight,
			Block:  state.LastBlock,
		}
		blocks = append(blocks, blk)
	}

	if err := bi.commitBlocks(ctx, blocks, false); err != nil {
		return err
	}

	bi.logger.Debug("block reindex completed")
	return nil
}

func (bi *BlockIndexer) commitBlock(ctx context.Context, block *roothash.AnnotatedBlock, notify bool) error {
	return bi.commitBlocks(ctx, []*roothash.AnnotatedBlock{block}, notify)
}

func (bi *BlockIndexer) commitBlocks(ctx context.Context, blocks []*roothash.AnnotatedBlock, notify bool) error {
	if len(blocks) == 0 {
		return nil
	}

	var results []*roothash.RoundResults
	for _, blk := range blocks {
		result, err := bi.consensus.RootHash().GetLastRoundResults(ctx, &roothash.RuntimeRequest{
			RuntimeID: bi.history.RuntimeID(),
			Height:    blk.Height,
		})
		if err != nil {
			bi.logger.Error("failed to fetch round results",
				"err", err,
				"height", blk.Height,
			)
			return fmt.Errorf("failed to fetch round results: %w", err)
		}
		results = append(results, result)
	}

	bi.logger.Debug("committing blocks",
		"start_round", blocks[0].Block.Header.Round,
		"end_round", blocks[len(blocks)-1].Block.Header.Round,
		logging.LogEvent, roothash.LogEventHistoryReindexing,
	)

	if err := bi.history.CommitBatch(blocks, results, notify); err != nil {
		bi.logger.Error("failed to commit blocks",
			"err", err,
		)
		return fmt.Errorf("failed to commit blocks: %w", err)
	}

	return nil
}
