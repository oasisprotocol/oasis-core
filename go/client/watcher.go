package client

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

type watchRequest struct {
	id     *hash.Hash
	ctx    context.Context
	respCh chan *watchResult
}

func (w *watchRequest) send(res *watchResult) error {
	select {
	case <-w.ctx.Done():
		return context.Canceled
	case w.respCh <- res:
		return nil
	}
}

type watchResult struct {
	result    []byte
	err       error
	newLeader *node.Node
}

type blockWatcher struct {
	service.BaseBackgroundService

	common *clientCommon
	id     signature.PublicKey

	watched map[hash.Hash]*watchRequest
	newCh   chan *watchRequest

	leader *node.Node

	stopCh chan struct{}
}

func (w *blockWatcher) refreshCommittee(height int64) error {
	committees, err := w.common.scheduler.GetCommittees(w.common.ctx, w.id, height)
	if err != nil {
		return err
	}

	var committee *scheduler.Committee
	for _, c := range committees {
		if c.Kind != scheduler.KindTransactionScheduler {
			continue
		}
		committee = c
		break
	}

	if committee == nil {
		return errors.New("client/watcher: no transaction scheduler committee after epoch transition")
	}

	var leader *node.Node
	for _, node := range committee.Members {
		if node.Role != scheduler.Leader {
			continue
		}
		leader, err = w.common.registry.GetNode(w.common.ctx, node.PublicKey)
		if err != nil {
			return err
		}
		break
	}
	if leader == nil {
		return errors.New("client/watcher: no leader in new committee")
	}

	// Update our notion of the leader and tell every client to resubmit.
	w.leader = leader
	for key, watch := range w.watched {
		res := &watchResult{
			newLeader: leader,
		}
		if watch.send(res) != nil {
			delete(w.watched, key)
		}
	}
	return nil
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
traverseLoop:
	for txHash, watch := range w.watched {
		tx, err := tree.GetTransaction(ctx, txHash)
		switch err {
		case nil:
		case transaction.ErrNotFound:
			continue traverseLoop
		default:
			w.Logger.Error("can't get block I/O from storage", "err", err)
			return
		}

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
			if w.leader != nil {
				res := &watchResult{
					newLeader: w.leader,
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
			if err := w.refreshCommittee(height); err != nil {
				w.Logger.Error("error getting new committee data, waiting for next epoch", "err", err)
				w.leader = nil
				continue
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

func newWatcher(common *clientCommon, id signature.PublicKey) (*blockWatcher, error) {
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
