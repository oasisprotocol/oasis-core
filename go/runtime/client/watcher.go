package client

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
)

const (
	// retryInterval in consensus blocks.
	retryInterval = 60
)

type watchRequest struct {
	id     *hash.Hash
	ctx    context.Context
	respCh chan *watchResult
	height int64
}

func (w *watchRequest) send(res *watchResult, height int64) error {
	// Update last sent height.
	w.height = height

	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case w.respCh <- res:
		return nil
	}
}

type watchResult struct {
	result       []byte
	groupVersion int64
}

type blockWatcher struct {
	service.BaseBackgroundService

	common *clientCommon
	id     common.Namespace

	watched map[hash.Hash]*watchRequest
	newCh   chan *watchRequest

	stopCh chan struct{}
}

func (w *blockWatcher) checkBlock(blk *block.Block) {
	if blk.Header.IORoot.IsEmpty() {
		return
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
		w.Logger.Error("can't get block I/O from storage", "err", err)
		return
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
}

func (w *blockWatcher) watch() {
	defer func() {
		close(w.newCh)
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

	consensusBlocks, consensusBlocksSub, err := w.common.consensus.WatchBlocks(w.common.ctx)
	if err != nil {
		w.Logger.Error("failed to subscribe to consensus blocks",
			"err", err,
		)
		return
	}
	defer consensusBlocksSub.Close()

	// If we were just started, refresh the committee information from any
	// block, otherwise just from epoch transition blocks.
	var gotInitialCommittee bool
	// latestGroupVersion contains the latest known committee group version.
	var latestGroupVersion int64
	// latestHeight contains the latest known consensus block height.
	var latestHeight int64
	for {
		// Wait for stuff to happen.
		select {
		case blk := <-blocks:
			// Check block.
			w.checkBlock(blk.Block)

			// If this is the initial block or an epoch transition block,
			// update latest known group version and resend all transactions.
			if gotInitialCommittee && blk.Block.Header.HeaderType != block.EpochTransition {
				continue
			}

			// Get group version.
			var ce api.EpochTime
			ce, err = w.common.consensus.EpochTime().GetEpoch(w.common.ctx, blk.Height)
			if err != nil {
				w.Logger.Error("error getting epoch block",
					"err", err,
					"height", blk.Height,
				)
				continue
			}
			var ch int64
			ch, err = w.common.consensus.EpochTime().GetEpochBlock(w.common.ctx, ce)
			if err != nil {
				w.Logger.Error("error getting epoch number",
					"err", err,
					"height", blk.Height,
				)
				continue
			}
			latestGroupVersion = ch

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
			gotInitialCommittee = true

		case blk := <-consensusBlocks:
			if blk == nil {
				break
			}
			latestHeight = blk.Height

			// Check if any transactions are due for a retry.
			for key, watch := range w.watched {
				if watch.height == 0 {
					continue
				}
				if (latestHeight - retryInterval) < watch.height {
					continue
				}
				res := &watchResult{
					groupVersion: latestGroupVersion,
				}
				w.Logger.Debug("resending message",
					"key", key,
					"latest_height", latestHeight,
					"retry_interval", retryInterval,
					"watch_height", watch.height,
				)
				if watch.send(res, latestHeight) != nil {
					delete(w.watched, key)
				}
			}

		case newWatch := <-w.newCh:
			w.watched[*newWatch.id] = newWatch

			res := &watchResult{
				groupVersion: latestGroupVersion,
			}
			if newWatch.send(res, latestHeight) != nil {
				delete(w.watched, *newWatch.id)
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

func newWatcher(common *clientCommon, id common.Namespace, p2pSvc *p2p.P2P) (*blockWatcher, error) {
	// Register handler.
	p2pSvc.RegisterHandler(id, &p2p.BaseHandler{})

	svc := service.NewBaseBackgroundService("client/watcher")
	watcher := &blockWatcher{
		BaseBackgroundService: *svc,
		common:                common,
		id:                    id,
		watched:               make(map[hash.Hash]*watchRequest),
		newCh:                 make(chan *watchRequest),
		stopCh:                make(chan struct{}),
	}
	return watcher, nil
}
