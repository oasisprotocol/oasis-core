package client

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
)

type watchRequest struct {
	id     hash.Hash
	ctx    context.Context
	respCh chan *watchResult
	height int64
}

func (w *watchRequest) send(res *watchResult, height int64) error {
	w.height = height

	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case w.respCh <- res:
		return nil
	}
}

type watchResult struct {
	err          error
	result       []byte
	groupVersion int64
}

type blockWatcher struct {
	service.BaseBackgroundService

	common *clientCommon
	id     common.Namespace

	watched map[hash.Hash]*watchRequest
	newCh   chan *watchRequest

	maxTransactionAge int64

	toBeChecked []*block.Block

	stopCh chan struct{}
}

func (w *blockWatcher) checkBlock(blk *block.Block) error {
	if blk.Header.IORoot.IsEmpty() {
		return nil
	}

	// If there's no pending transactions, we can skip the check.
	if len(w.watched) == 0 {
		return nil
	}

	ctx := w.common.ctx
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
		Hash:      blk.Header.IORoot,
	}

	tree := transaction.NewTree(w.common.storage, ioRoot)
	defer tree.Close()

	// Check if there's anything interesting in this block.
	var txHashes []hash.Hash
	for txHash := range w.watched {
		txHashes = append(txHashes, txHash)
	}

	matches, err := tree.GetTransactionMultiple(ctx, txHashes)
	if err != nil {
		return fmt.Errorf("error getting block I/O from storage: %w", err)
	}

	for txHash, tx := range matches {
		watch := w.watched[txHash]
		res := &watchResult{
			result: tx.Output,
		}

		// Ignore errors, the watch is getting deleted anyway.
		_ = watch.send(res, 0)
		close(watch.respCh)
		delete(w.watched, txHash)
	}

	return nil
}

func (w *blockWatcher) getGroupVersion(height int64) (int64, error) {
	epoch, err := w.common.consensus.Beacon().GetEpoch(w.common.ctx, height)
	if err != nil {
		return 0, fmt.Errorf("failed querying for epoch: %w", err)
	}
	return w.common.consensus.Beacon().GetEpochBlock(w.common.ctx, epoch)
}

func (w *blockWatcher) watch() {
	defer func() {
		for _, watch := range w.watched {
			close(watch.respCh)
		}
		w.BaseBackgroundService.Stop()
	}()

	// Start watching roothash blocks.
	blocks, blocksSub, err := w.common.consensus.RootHash().WatchBlocks(w.id)
	if err != nil {
		w.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	// Start watching consensus blocks.
	consensusBlocks, consensusBlocksSub, err := w.common.consensus.WatchBlocks(w.common.ctx)
	if err != nil {
		w.Logger.Error("failed to subscribe to consensus blocks",
			"err", err,
		)
		return
	}
	defer consensusBlocksSub.Close()

	// latestHeight contains the latest known consensus block height.
	var latestHeight int64
	// latestGroupVersion contains the latest known committee group version.
	var latestGroupVersion int64
	// Wait for first consensus block before proceeding.
	select {
	case <-w.stopCh:
		return
	case <-w.common.ctx.Done():
		return
	case blk := <-consensusBlocks:
		latestHeight = blk.Height
		latestGroupVersion, err = w.getGroupVersion(blk.Height)
		if err != nil {
			w.Logger.Error("failed querying for latest group version",
				"err", err,
			)
			return
		}
	}

	for {
		// Wait for stuff to happen.
		select {
		case blk := <-blocks:
			w.toBeChecked = append(w.toBeChecked, blk.Block)

			var failedBlocks []*block.Block
			for _, b := range w.toBeChecked {
				if err = w.checkBlock(b); err != nil {
					w.Logger.Error("error checking block",
						"err", err,
						"round", b.Header.Round,
					)
					failedBlocks = append(failedBlocks, b)
				}
			}
			if len(failedBlocks) > 0 {
				w.Logger.Warn("failed roothash blocks",
					"num_failed_blocks", len(failedBlocks),
				)
			}
			w.toBeChecked = failedBlocks

			// If this is an epoch transition block, update latest known group
			// version and resend all transactions.
			if blk.Block.Header.HeaderType != block.EpochTransition {
				continue
			}

			// Get group version.
			latestGroupVersion, err = w.getGroupVersion(blk.Height)
			if err != nil {
				w.Logger.Error("failed querying for latest group version",
					"err", err,
				)
				continue
			}

			// Tell every client to resubmit as messages with old groupVersion
			// will be discarded.
			for key, watch := range w.watched {
				res := &watchResult{
					groupVersion: latestGroupVersion,
				}
				if watch.send(res, latestHeight) != nil {
					delete(w.watched, key)
				}
			}
		case blk := <-consensusBlocks:
			if blk == nil {
				break
			}
			latestHeight = blk.Height

			// Check if any transaction is considered expired.
			for key, watch := range w.watched {
				if (latestHeight - w.maxTransactionAge) < watch.height {
					continue
				}
				w.Logger.Debug("expired transaction",
					"key", key,
					"latest_height", latestHeight,
					"max_transaction_age", w.maxTransactionAge,
					"watch_height", watch.height,
				)
				res := &watchResult{
					err: api.ErrTransactionExpired,
				}
				// Ignore errors, the watch is getting deleted anyway.
				_ = watch.send(res, 0)
				close(watch.respCh)
				delete(w.watched, key)
			}
		case newWatch := <-w.newCh:
			w.watched[newWatch.id] = newWatch

			res := &watchResult{
				groupVersion: latestGroupVersion,
			}
			if newWatch.send(res, latestHeight) != nil {
				delete(w.watched, newWatch.id)
			}

		case <-w.stopCh:
			w.Logger.Info("stop requested, aborting watcher")
			return
		case <-w.common.ctx.Done():
			w.Logger.Info("context cancelled, aborting watcher")
			return
		}
	}
}

// Start starts a new per-runtime block watcher.
func (w *blockWatcher) Start() error {
	go w.watch()
	return nil
}

// Stop initiates watcher shutdown.
func (w *blockWatcher) Stop() {
	close(w.stopCh)
}

func newWatcher(common *clientCommon, id common.Namespace, p2pSvc *p2p.P2P, maxTransactionAge int64) (*blockWatcher, error) {
	// Register handler.
	p2pSvc.RegisterHandler(id, &p2p.BaseHandler{})

	svc := service.NewBaseBackgroundService("client/watcher")
	watcher := &blockWatcher{
		BaseBackgroundService: *svc,
		common:                common,
		id:                    id,
		maxTransactionAge:     maxTransactionAge,
		watched:               make(map[hash.Hash]*watchRequest),
		newCh:                 make(chan *watchRequest),
		stopCh:                make(chan struct{}),
	}
	return watcher, nil
}
