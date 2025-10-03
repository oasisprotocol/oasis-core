package history

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const (
	statusStarted    = "started"
	statusReindexing = "reindexing"
	statusIndexing   = "indexing"
	statusStopped    = "stopped"
)

// IndexerStatus is the status of runtime history indexer.
type IndexerStatus struct {
	// Status is the concise status of runtime history indexer state.
	Status string `json:"status"`

	// LastRound is the last runtime round that was indexed.
	LastRound uint64 `json:"last_round"`

	// ReindexStatus is history reindex status.
	//
	// It is nil unless during history reindex.
	ReindexStatus *ReindexStatus `json:"reindex_status,omitempty"`
}

type ReindexStatus struct {
	// BatchSize is the number of blocks to reindex in a single batch.
	BatchSize uint16 `json:"batch_size"`
	// LastHeight is the last consensus height that was indexed.
	LastHeight int64 `json:"last_height"`
	// StartHeight is the first height of history reindex interval.
	StartHeight int64 `json:"start_height"`
	// EndHeight is the last height of history reindex interval.
	EndHeight int64 `json:"end_height"`
	// ETA is expected time of history reindex completition.
	ETA time.Time `json:"eta"`
}

const (
	maxPendingBlocks = 10
)

// BlockIndexer is responsible for indexing and committing finalized
// runtime blocks from the consensus into the runtime history.
type BlockIndexer struct {
	mu       sync.RWMutex
	startOne cmSync.One

	consensus consensus.Service
	history   History
	batchSize uint16

	status      string
	lastHeight  int64
	startHeight int64
	endHeight   int64
	lastRound   uint64
	started     time.Time

	logger *logging.Logger
}

// NewBlockIndexer creates a new block indexer.
func NewBlockIndexer(consensus consensus.Service, history History, batchSize uint16) *BlockIndexer {
	logger := logging.GetLogger("runtime/history/indexer").With("runtime_id", history.RuntimeID())

	return &BlockIndexer{
		startOne:  cmSync.NewOne(),
		consensus: consensus,
		history:   history,
		batchSize: batchSize,
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

// Status returns runtime block history indexer status.
func (bi *BlockIndexer) Status() *IndexerStatus {
	bi.mu.RLock()
	defer bi.mu.RUnlock()

	status := &IndexerStatus{
		Status:    bi.status,
		LastRound: bi.lastRound,
	}

	if bi.status != statusReindexing {
		return status
	}

	elapsed := time.Since(bi.started).Milliseconds()
	remaining := elapsed * (bi.endHeight - bi.lastHeight) / max((bi.lastHeight-bi.startHeight+1), 1)
	eta := time.Now().Add(time.Duration(remaining) * time.Millisecond)
	status.ReindexStatus = &ReindexStatus{
		BatchSize:   bi.batchSize,
		LastHeight:  bi.lastHeight,
		StartHeight: bi.startHeight,
		EndHeight:   bi.endHeight,
		ETA:         eta,
	}

	return status
}

func (bi *BlockIndexer) run(ctx context.Context) {
	bi.logger.Info("starting")

	bi.mu.Lock()
	bi.status = statusStarted
	bi.mu.Unlock()

	// Subscribe to new runtime blocks.
	blkCh, blkSub, err := bi.consensus.RootHash().WatchBlocks(ctx, bi.history.RuntimeID())
	if err != nil {
		bi.logger.Error("failed to watch blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	// Reindex blocks up to the latest.
	if err = bi.reindex(ctx, blkCh); err != nil {
		bi.logger.Error("failed to reindex blocks",
			"err", err,
		)
		return
	}

	// Mark that reindex has completed.
	if err = bi.history.SetInitialized(); err != nil {
		bi.logger.Error("failed to initialize block history",
			"err", err,
		)
		return
	}

	// Index new blocks.
	bi.index(ctx, blkCh)
	bi.logger.Info("stopping")

	bi.mu.Lock()
	bi.status = statusStopped
	bi.mu.Unlock()
}

func (bi *BlockIndexer) index(ctx context.Context, blkCh <-chan *roothash.AnnotatedBlock) {
	bi.logger.Info("indexing")

	bi.mu.Lock()
	bi.status = statusIndexing
	bi.mu.Unlock()

	retry := time.Duration(math.MaxInt64)
	boff := cmnBackoff.NewExponentialBackOff()
	boff.Reset()

	blks := make([]*roothash.AnnotatedBlock, 0, 1)
	for {
		select {
		case blk := <-blkCh:
			blks = append(blks, blk)
		case <-time.After(retry):
		case <-ctx.Done():
			return
		}

		if len(blks) > maxPendingBlocks {
			bi.logger.Error("too many pending blocks for commit, terminating")
			return
		}

		if err := bi.commitBlocks(blks); err != nil {
			bi.logger.Warn("failed to commit blocks", "err", err)
			retry = boff.NextBackOff()
			continue
		}

		blks = blks[:0]
		retry = math.MaxInt64
		boff.Reset()
	}
}

func (bi *BlockIndexer) reindex(ctx context.Context, blkCh <-chan *roothash.AnnotatedBlock) error {
	bi.logger.Info("reindexing",
		logging.LogEvent, roothash.LogEventHistoryReindexing,
	)

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	reindexCh := make(chan int64, 1)
	reindexDoneCh := make(chan int64, 1)

	// Start a goroutine to handle reindex requests.
	wg.Go(func() {
		retry := time.Duration(math.MaxInt64)
		boff := cmnBackoff.NewExponentialBackOff()
		boff.Reset()

		var height int64
		for {
			select {
			case height = <-reindexCh:
			case <-time.After(retry):
			case <-ctx.Done():
				return
			}
			// Reindex blocks up to the specified height.
			if err := bi.reindexTo(ctx, height); err != nil {
				bi.logger.Warn("failed to reindex blocks",
					"err", err,
					"height", height,
				)
				retry = boff.NextBackOff()
				continue
			}
			retry = math.MaxInt64
			boff.Reset()
			// Notify that reindex has been completed.
			sendToChannel(reindexDoneCh, height)
		}
	})

	// Reindex blocks up to the latest block.
	var blk *roothash.AnnotatedBlock
	for {
		select {
		case blk = <-blkCh:
			// Send a new request with the latest height.
			sendToChannel(reindexCh, blk.Height)
			continue
		case height := <-reindexDoneCh:
			// Stop once reindex catches up.
			if height != blk.Height {
				continue
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		break
	}

	// Commit the last block manually, if the height at which the block
	// was published is not available due to state sync from a newer height.
	// This ensures that there is always at least one block in the history.
	height, err := bi.history.LastConsensusHeight()
	if err != nil {
		return fmt.Errorf("failed to fetch last consensus height: %w", err)
	}
	if height != blk.Height {
		if err := bi.commitBlocks([]*roothash.AnnotatedBlock{blk}); err != nil {
			return fmt.Errorf("failed to commit blocks: %w", err)
		}
	}

	bi.logger.Info("reindex completed")
	return nil
}

func (bi *BlockIndexer) reindexTo(ctx context.Context, height int64) error {
	lastHeight, err := bi.history.LastConsensusHeight()
	if err != nil {
		return fmt.Errorf("failed to get last indexed height: %w", err)
	}
	startHeight := lastHeight + 1 // +1 since we want the last non-seen height.

	lastRetainedHeight, err := bi.consensus.Core().GetLastRetainedHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last retained height: %w", err)
	}

	if startHeight < lastRetainedHeight {
		bi.logger.Debug("skipping pruned heights",
			"last_retained_height", lastRetainedHeight,
			"start_height", startHeight,
		)
		startHeight = lastRetainedHeight
	}

	bi.mu.Lock()
	bi.status = statusReindexing
	bi.endHeight = height
	if bi.startHeight == 0 {
		bi.lastHeight = lastHeight
		bi.startHeight = startHeight
		bi.started = time.Now()
	}
	bi.mu.Unlock()

	batchSize := int64(bi.batchSize)
	for start := startHeight; start <= height; start += batchSize {
		end := min(start+batchSize-1, height)
		if err = bi.reindexRange(ctx, start, end); err != nil {
			return fmt.Errorf("failed to reindex batch: %w", err)
		}
	}

	return nil
}

func (bi *BlockIndexer) reindexRange(ctx context.Context, start int64, end int64) error {
	bi.logger.Debug("reindexing blocks",
		"start_height", start,
		"end_height", end,
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

	if err := bi.commitBlocks(blocks); err != nil {
		return fmt.Errorf("failed to commit blocks: %w", err)
	}

	bi.mu.Lock()
	bi.lastHeight = end
	bi.mu.Unlock()

	bi.logger.Debug("block reindex completed")
	return nil
}

func (bi *BlockIndexer) commitBlocks(blocks []*roothash.AnnotatedBlock) error {
	if len(blocks) == 0 {
		return nil
	}

	bi.logger.Debug("committing blocks",
		"start_round", blocks[0].Block.Header.Round,
		"end_round", blocks[len(blocks)-1].Block.Header.Round,
	)

	if err := bi.history.Commit(blocks); err != nil {
		return err
	}

	bi.mu.Lock()
	defer bi.mu.Unlock()
	lastBlk := blocks[len(blocks)-1]
	bi.lastRound = lastBlk.Block.Header.Round

	return nil
}

// sendToChannel sends a value to the channel, overwriting any pending value.
func sendToChannel[T any](ch chan T, value T) {
	select {
	case <-ch:
	default:
	}
	ch <- value
}
