// Package history implements the runtime block history and pruning policy.
package history

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/config"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// DbFilename is the filename of the history database.
const DbFilename = "history.db"

var _ History = (*runtimeHistory)(nil)

// Factory is the runtime history factory interface.
type Factory func(runtimeID common.Namespace, dataDir string) (History, error)

// History is the runtime history interface.
type History interface {
	roothash.BlockHistory

	// Pruner returns the history pruner.
	Pruner() Pruner

	// Close closes the history keeper.
	Close()
}

type runtimeHistory struct {
	runtimeID common.Namespace

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc

	db             *DB
	blocksNotifier *pubsub.Broker

	// Last storage synced round as reported by the storage backend (if enabled).
	syncRoundLock    sync.RWMutex
	firstSyncedRound uint64
	lastSyncedRound  uint64

	hasLocalStorage bool

	pruner  Pruner
	pruneCh *channels.RingChannel
	stopCh  chan struct{}
	quitCh  chan struct{}
}

func (h *runtimeHistory) RuntimeID() common.Namespace {
	return h.runtimeID
}

func (h *runtimeHistory) Commit(blk *roothash.AnnotatedBlock, result *roothash.RoundResults, notify bool) error {
	return h.CommitBatch([]*roothash.AnnotatedBlock{blk}, []*roothash.RoundResults{result}, notify)
}

func (h *runtimeHistory) CommitBatch(blks []*roothash.AnnotatedBlock, results []*roothash.RoundResults, notify bool) error {
	if len(blks) == 0 && len(results) == 0 {
		return nil
	}

	if err := h.db.commit(blks, results); err != nil {
		return err
	}

	// Notify the pruner what the new round is.
	lastBlk := blks[len(blks)-1]
	h.pruneCh.In() <- lastBlk.Block.Header.Round

	// If no local storage worker, notify the block watcher about new blocks,
	// otherwise the storage-sync-checkpoint will do the notification.
	if h.hasLocalStorage || !notify {
		return nil
	}
	for _, blk := range blks {
		h.blocksNotifier.Broadcast(blk)
	}

	return nil
}

func (h *runtimeHistory) GetBlock(_ context.Context, round uint64) (*roothash.AnnotatedBlock, error) {
	resolvedRound, err := h.resolveRound(round)
	if err != nil {
		return nil, err
	}
	return h.db.getBlock(resolvedRound)
}

func (h *runtimeHistory) GetEarliestBlock(context.Context) (*roothash.AnnotatedBlock, error) {
	return h.db.getEarliestBlock()
}

func (h *runtimeHistory) GetSyncedBlock(_ context.Context, round uint64) (*roothash.AnnotatedBlock, error) {
	resolvedRound, err := h.resolveSyncedRound(round)
	if err != nil {
		return nil, err
	}
	return h.db.getBlock(resolvedRound)
}

func (h *runtimeHistory) GetEarliestSyncedBlock(_ context.Context) (*roothash.AnnotatedBlock, error) {
	h.syncRoundLock.Lock()
	firstSyncedRound := h.firstSyncedRound
	h.syncRoundLock.Unlock()
	if firstSyncedRound == roothash.RoundInvalid {
		return nil, roothash.ErrNotFound
	}
	blk, err := h.db.getEarliestBlock()
	if err != nil {
		return nil, err
	}
	if blk.Block.Header.Round >= firstSyncedRound {
		return blk, nil
	}
	return h.db.getBlock(firstSyncedRound)
}

func (h *runtimeHistory) GetRoundResults(_ context.Context, round uint64) (*roothash.RoundResults, error) {
	resolvedRound, err := h.resolveRound(round)
	if err != nil {
		return nil, err
	}
	return h.db.getRoundResults(resolvedRound)
}

func (h *runtimeHistory) WatchBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *roothash.AnnotatedBlock)
	sub := h.blocksNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (h *runtimeHistory) WatchSyncedBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *roothash.AnnotatedBlock)
	sub := h.blocksNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (h *runtimeHistory) WaitRound(ctx context.Context, round uint64) (uint64, error) {
	return h.waitRound(ctx, round, false)
}

func (h *runtimeHistory) WaitRoundSynced(ctx context.Context, round uint64) (uint64, error) {
	return h.waitRound(ctx, round, true)
}

func (h *runtimeHistory) waitRound(ctx context.Context, round uint64, synced bool) (uint64, error) {
	watchBlocks := h.WatchBlocks
	if synced {
		watchBlocks = h.WatchSyncedBlocks
	}

	blkCh, sub, err := watchBlocks()
	if err != nil {
		return 0, fmt.Errorf("runtime/history: watch blocks failure: %w", err)
	}
	defer sub.Close()
	for {
		select {
		case annBlk, ok := <-blkCh:
			if !ok {
				return 0, fmt.Errorf("runtime/history: watch blocks channel closed unexpectedly")
			}

			if annBlk.Block.Header.Round >= round {
				return annBlk.Block.Header.Round, nil
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (h *runtimeHistory) LastRound() (uint64, error) {
	return h.resolveRound(roothash.RoundLatest)
}

func (h *runtimeHistory) LastSyncedRound() (uint64, error) {
	return h.resolveSyncedRound(roothash.RoundLatest)
}

func (h *runtimeHistory) LastConsensusHeight() (int64, error) {
	meta, err := h.db.metadata()
	if err != nil {
		return 0, err
	}
	return meta.LastConsensusHeight, nil
}

func (h *runtimeHistory) StorageSyncCheckpoint(round uint64) error {
	if config.GlobalConfig.Mode == config.ModeArchive {
		// If we are in archive mode, ignore storage sync checkpoints.
		return nil
	}

	if !h.hasLocalStorage {
		panic("received storage sync checkpoint when local storage worker is disabled")
	}

	h.syncRoundLock.Lock()
	defer h.syncRoundLock.Unlock()
	switch {
	case h.lastSyncedRound == roothash.RoundInvalid:
	case h.lastSyncedRound == round:
		return nil
	case h.lastSyncedRound > round:
		return fmt.Errorf("runtime/history: storage sync checkpoint at lower height (current: %d wanted: %d)", h.lastSyncedRound, round)
	default:
	}

	blk, err := h.db.getBlock(round)
	if err != nil {
		return fmt.Errorf("runtime/history: storage sync block not found in history: %w", err)
	}
	if h.firstSyncedRound == roothash.RoundInvalid {
		h.firstSyncedRound = round
	}
	h.lastSyncedRound = round
	h.blocksNotifier.Broadcast(blk)

	return nil
}

func (h *runtimeHistory) Pruner() Pruner {
	return h.pruner
}

func (h *runtimeHistory) Close() {
	h.cancelCtx()
	close(h.stopCh)
	<-h.quitCh

	h.db.close()
}

func (h *runtimeHistory) pruneWorker() {
	defer close(h.quitCh)

	interval := h.pruner.PruneInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var round interface{}
			select {
			case round = <-h.pruneCh.Out():
			case <-h.stopCh:
				h.logger.Debug("prune worker is terminating")
				return
			}

			h.logger.Debug("pruning runtime history",
				"round", round.(uint64),
			)

			if err := h.pruner.Prune(round.(uint64)); err != nil {
				h.logger.Error("failed to prune",
					"err", err,
				)
				continue
			}
		case <-h.stopCh:
			h.logger.Debug("prune worker is terminating")
			return
		}
	}
}

func (h *runtimeHistory) resolveRound(round uint64) (uint64, error) {
	if round == roothash.RoundLatest {
		meta, err := h.db.metadata()
		if err != nil {
			return 0, err
		}
		return meta.LastRound, nil
	}
	return round, nil
}

func (h *runtimeHistory) resolveSyncedRound(round uint64) (uint64, error) {
	h.syncRoundLock.RLock()
	firstSyncedRound := h.firstSyncedRound
	lastSyncedRound := h.lastSyncedRound
	h.syncRoundLock.RUnlock()

	if lastSyncedRound == roothash.RoundInvalid {
		return 0, roothash.ErrNotFound
	}
	if round == roothash.RoundLatest {
		meta, err := h.db.metadata()
		if err != nil {
			return 0, err
		}
		round = min(meta.LastRound, lastSyncedRound)
	}
	if round > lastSyncedRound || round < firstSyncedRound {
		return 0, roothash.ErrNotFound
	}
	return round, nil
}

// New creates a new runtime history keeper.
func New(runtimeID common.Namespace, dataDir string, prunerFactory PrunerFactory, hasLocalStorage bool) (History, error) {
	db, err := newDB(filepath.Join(dataDir, DbFilename), runtimeID)
	if err != nil {
		return nil, err
	}

	pruner, err := prunerFactory(runtimeID, db)
	if err != nil {
		return nil, err
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	h := &runtimeHistory{
		runtimeID:        runtimeID,
		logger:           logging.GetLogger("runtime/history").With("runtime_id", runtimeID),
		ctx:              ctx,
		cancelCtx:        cancelCtx,
		db:               db,
		hasLocalStorage:  hasLocalStorage,
		blocksNotifier:   pubsub.NewBroker(true),
		firstSyncedRound: roothash.RoundInvalid,
		lastSyncedRound:  roothash.RoundInvalid,
		pruner:           pruner,
		pruneCh:          channels.NewRingChannel(1),
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
	}

	go h.pruneWorker()

	return h, nil
}

// NewFactory creates a new runtime history keeper factory.
func NewFactory(prunerFactory PrunerFactory, haveLocalStorageWorker bool) Factory {
	return func(runtimeID common.Namespace, dataDir string) (History, error) {
		return New(runtimeID, dataDir, prunerFactory, haveLocalStorageWorker)
	}
}
