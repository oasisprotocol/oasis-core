package client

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/service"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/runtime/committee"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	txnscheduler "github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler/api"
)

type watchRequest struct {
	id     *hash.Hash
	ctx    context.Context
	respCh chan *watchResult
}

func (w *watchRequest) send(res *watchResult) error {
	select {
	case <-w.ctx.Done():
		return w.ctx.Err()
	case w.respCh <- res:
		return nil
	}
}

type watchResult struct {
	result                []byte
	err                   error
	newTxnschedulerClient txnscheduler.TransactionScheduler
}

type blockWatcher struct {
	service.BaseBackgroundService

	common *clientCommon
	id     common.Namespace

	watched map[hash.Hash]*watchRequest
	newCh   chan *watchRequest

	committeeWatcher committee.Watcher
	committeeClient  committee.Client

	stopCh chan struct{}
}

func (w *blockWatcher) checkBlock(blk *block.Block) {
	if blk.Header.IORoot.IsEmpty() {
		return
	}

	ctx := w.common.ctx
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
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
		_ = watch.send(res)
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

	// If we were just started, refresh the committee information from any
	// block, otherwise just from epoch transition blocks.
	gotFirstBlock := false
	// Start watching roothash blocks.
	blocks, blocksSub, err := w.common.roothash.WatchBlocks(w.id)
	if err != nil {
		w.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	for {
		var current *block.Block
		var height int64

		// Wait for stuff to happen.
		select {
		case blk := <-blocks:
			current = blk.Block
			height = blk.Height

		case newWatch := <-w.newCh:
			w.watched[*newWatch.id] = newWatch
			if conn := w.committeeClient.GetConnection(); conn != nil {
				client := txnscheduler.NewTransactionSchedulerClient(conn)
				res := &watchResult{
					newTxnschedulerClient: client,
				}
				if newWatch.send(res) != nil {
					delete(w.watched, *newWatch.id)
				}
			}

		case <-w.stopCh:
			w.Logger.Info("stop requested, aborting watcher")
			return
		case <-w.common.ctx.Done():
			w.Logger.Info("context cancelled, aborting watcher")
			return
		}

		if current == nil || current.Header.HeaderType == block.RoundFailed {
			continue
		}

		// Find a new committee leader.
		if current.Header.HeaderType == block.EpochTransition || !gotFirstBlock {
			if err := w.committeeWatcher.EpochTransition(w.common.ctx, height); err != nil {
				w.Logger.Error("error getting new committee data, waiting for next epoch",
					"err", err,
				)
				continue
			}

			if err := w.committeeClient.EnsureVersion(w.common.ctx, height); err != nil {
				w.Logger.Error("error waiting for committee update to complete",
					"err", err)
			}
			conn := w.committeeClient.GetConnection()
			if conn != nil {
				client := txnscheduler.NewTransactionSchedulerClient(conn)

				// Tell every client to resubmit as nothing further can be finalized by this committee.
				for key, watch := range w.watched {
					res := &watchResult{
						newTxnschedulerClient: client,
					}
					if watch.send(res) != nil {
						delete(w.watched, key)
					}
				}
			}

		}
		gotFirstBlock = true

		// Check this new block.
		if current.Header.HeaderType == block.Normal {
			w.checkBlock(current)
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

func newWatcher(common *clientCommon, id common.Namespace) (*blockWatcher, error) {
	committeeWatcher, err := committee.NewWatcher(
		common.ctx,
		common.scheduler,
		common.registry,
		id,
		scheduler.KindComputeTxnScheduler,
		committee.WithFilter(func(cn *scheduler.CommitteeNode) bool {
			// We are only interested in the transaction scheduler leader.
			return cn.Role == scheduler.Leader
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("client/watcher: failed to create committee watcher: %w", err)
	}

	committeeClient, err := committee.NewClient(common.ctx, committeeWatcher.Nodes())
	if err != nil {
		return nil, fmt.Errorf("client/watcher: failed to create committee client: %w", err)
	}

	svc := service.NewBaseBackgroundService("client/watcher")
	watcher := &blockWatcher{
		BaseBackgroundService: *svc,
		common:                common,
		id:                    id,
		committeeWatcher:      committeeWatcher,
		committeeClient:       committeeClient,
		watched:               make(map[hash.Hash]*watchRequest),
		newCh:                 make(chan *watchRequest),
		stopCh:                make(chan struct{}),
	}
	return watcher, nil
}
