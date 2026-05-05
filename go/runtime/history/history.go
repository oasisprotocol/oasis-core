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
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// DbFilename is the filename of the history database.
const DbFilename = "history.db"

var _ History = (*runtimeHistory)(nil)

// Factory is the runtime history factory interface.
type Factory func(runtimeID common.Namespace, dataDir string) (History, error)

// History is the runtime history interface.
type History interface {
	roothash.BlockHistory
	consensus.StatePruneHandler

	// Pruner returns the history pruner.
	Pruner() Pruner

	// PruneBefore prunes runtime history before the given round.
	PruneBefore(round uint64) (uint64, error)

	// Compact triggers compaction of the History underlying storage engine.
	Compact() error

	// Close closes the history keeper.
	Close()
}

type runtimeHistory struct {
	runtimeID common.Namespace

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc

	db                      *DB
	syncedBlocksNotifier    *pubsub.Broker
	committedBlocksNotifier *pubsub.Broker

	// Last storage synced round as reported by the storage backend (if enabled).
	syncRoundLock          sync.RWMutex
	lastStorageSyncedRound uint64

	honorStorageSync bool

	pruner  Pruner
	pruneCh *channels.RingChannel
	initCh  chan struct{}
	stopCh  chan struct{}
	quitCh  chan struct{}
}

func (h *runtimeHistory) RuntimeID() common.Namespace {
	return h.runtimeID
}

func (h *runtimeHistory) Initialized() <-chan struct{} {
	return h.initCh
}

func (h *runtimeHistory) SetInitialized() error {
	select {
	case <-h.initCh:
		return fmt.Errorf("already initialized")
	default:
		close(h.initCh)
	}

	blk, err := h.db.getLastBlock()
	switch err {
	case nil:
	case roothash.ErrNotFound:
		return nil
	default:
		return err
	}
	h.committedBlocksNotifier.Broadcast(blk)

	return nil
}

func (h *runtimeHistory) Commit(blks []*roothash.AnnotatedBlock) error {
	if len(blks) == 0 {
		return nil
	}

	if err := h.db.commit(blks); err != nil {
		return err
	}

	// Notify the pruner what the new round is.
	lastBlk := blks[len(blks)-1]
	h.pruneCh.In() <- lastBlk.Block.Header.Round

	// Notify about new blocks only when initialized.
	select {
	case <-h.initCh:
	default:
		return nil
	}

	// If no local storage worker, notify the block watcher about new blocks,
	// otherwise the storage-sync-checkpoint will do the notification.
	for _, blk := range blks {
		h.committedBlocksNotifier.Broadcast(blk)
		if !h.honorStorageSync {
			h.syncedBlocksNotifier.Broadcast(blk)
		}
	}

	return nil
}

func (h *runtimeHistory) StorageSyncCheckpoint(round uint64) error {
	if config.GlobalConfig.Mode == config.ModeArchive {
		// If we are in archive mode, ignore storage sync checkpoints.
		return nil
	}

	if !h.honorStorageSync {
		panic("received storage sync checkpoint when local storage worker is disabled")
	}

	h.syncRoundLock.Lock()
	defer h.syncRoundLock.Unlock()
	switch {
	case h.lastStorageSyncedRound == roothash.RoundInvalid:
		// First sync, continue below.
	case round < h.lastStorageSyncedRound:
		return fmt.Errorf("runtime/history: storage sync checkpoint at lower round (current: %d wanted: %d)", h.lastStorageSyncedRound, round)
	case round == h.lastStorageSyncedRound:
		// Nothing to do.
		return nil
	default:
		// Continue below.
	}

	annBlk, err := h.db.getBlock(round)
	if err != nil {
		return fmt.Errorf("runtime/history: storage sync block not found in history: %w", err)
	}
	h.lastStorageSyncedRound = round

	// Notify about new blocks only when initialized.
	select {
	case <-h.initCh:
		h.syncedBlocksNotifier.Broadcast(annBlk)
	default:
	}

	return nil
}

func (h *runtimeHistory) LastStorageSyncedRound() (uint64, bool) {
	h.syncRoundLock.RLock()
	defer h.syncRoundLock.RUnlock()
	if h.lastStorageSyncedRound == roothash.RoundInvalid {
		return 0, false
	}
	return h.lastStorageSyncedRound, true
}

func (h *runtimeHistory) WatchBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	ch := make(chan *roothash.AnnotatedBlock)
	sub := h.syncedBlocksNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (h *runtimeHistory) WatchCommittedBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	ch := make(chan *roothash.AnnotatedBlock)
	sub := h.committedBlocksNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (h *runtimeHistory) WaitRoundSynced(ctx context.Context, round uint64) (uint64, error) {
	blkCh, sub, err := h.WatchBlocks()
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

func (h *runtimeHistory) LastConsensusHeight() (int64, error) {
	meta, err := h.db.metadata()
	if err != nil {
		return 0, err
	}

	return meta.LastConsensusHeight, nil
}

func (h *runtimeHistory) resolveRound(round uint64, includeStorage bool) (uint64, error) {
	switch round {
	case roothash.RoundLatest:
		// Determine the last round in case RoundLatest has been passed.
		meta, err := h.db.metadata()
		if err != nil {
			return 0, err
		}
		h.syncRoundLock.RLock()
		defer h.syncRoundLock.RUnlock()
		// Also take storage sync state into account.
		if includeStorage && h.honorStorageSync {
			if h.lastStorageSyncedRound == roothash.RoundInvalid {
				return 0, roothash.ErrNotFound
			}
			if h.lastStorageSyncedRound < meta.LastRound {
				return h.lastStorageSyncedRound, nil
			}
		}
		return meta.LastRound, nil
	default:
		h.syncRoundLock.RLock()
		defer h.syncRoundLock.RUnlock()
		// Ensure round exists.
		if includeStorage && h.honorStorageSync {
			if h.lastStorageSyncedRound == roothash.RoundInvalid {
				return 0, roothash.ErrNotFound
			}
			if h.lastStorageSyncedRound < round {
				return 0, roothash.ErrNotFound
			}
		}
		return round, nil
	}
}

func (h *runtimeHistory) GetCommittedBlock(ctx context.Context, round uint64) (*block.Block, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	resolvedRound, err := h.resolveRound(round, false)
	if err != nil {
		return nil, err
	}
	annBlk, err := h.db.getBlock(resolvedRound)
	if err != nil {
		return nil, err
	}
	return annBlk.Block, nil
}

func (h *runtimeHistory) GetBlock(ctx context.Context, round uint64) (*block.Block, error) {
	annBlk, err := h.GetAnnotatedBlock(ctx, round)
	if err != nil {
		return nil, err
	}
	return annBlk.Block, nil
}

func (h *runtimeHistory) GetAnnotatedBlock(ctx context.Context, round uint64) (*roothash.AnnotatedBlock, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	resolvedRound, err := h.resolveRound(round, true)
	if err != nil {
		return nil, err
	}
	return h.db.getBlock(resolvedRound)
}

func (h *runtimeHistory) GetEarliestBlock(ctx context.Context) (*block.Block, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	annBlk, err := h.db.getEarliestBlock()
	if err != nil {
		return nil, err
	}
	return annBlk.Block, nil
}

func (h *runtimeHistory) PruneBefore(round uint64) (uint64, error) {
	return h.db.pruneBefore(round)
}

// CanPruneConsenus returns no error when the specified consensus height has been already reindexed.
//
// Implements consensus.api.StatePruneHandler
func (h *runtimeHistory) CanPruneConsensus(height int64) error {
	lastHeight, err := h.LastConsensusHeight()
	if err != nil {
		h.logger.Warn("failed to fetch last consensus height for tracked runtime", "err", err)
		// We can't be sure if it is ok to prune this version, so prevent pruning to be safe.
		return fmt.Errorf("failed to fetch last consensus height for tracked runtime: %w", err)
	}

	if height > lastHeight {
		return fmt.Errorf("height %d not yet indexed for %s", height, h.RuntimeID())
	}

	return nil
}

func (h *runtimeHistory) Compact() error {
	h.logger.Info("compacting")

	if err := h.db.flatten(); err != nil {
		return fmt.Errorf("failed to flatten db: %w", err)
	}

	h.logger.Info("compaction completed")

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
			var round any
			select {
			case round = <-h.pruneCh.Out():
			case <-h.stopCh:
				h.logger.Debug("prune worker is terminating")
				return
			}

			h.logger.Debug("pruning runtime history", "round", round.(uint64))

			if err := h.pruner.Prune(round.(uint64)); err != nil {
				h.logger.Debug("failed to prune", "err", err)
				continue
			}
		case <-h.stopCh:
			h.logger.Debug("prune worker is terminating")
			return
		}
	}
}

// New creates a new runtime history keeper.
//
// If honorStorageSync is true, synced block notifications and block lookups honor the last storage round
// which was synced to runtime storage (see [History.StorageSyncCheckpoint]).
func New(runtimeID common.Namespace, dataDir string, prunerFactory PrunerFactory, honorStorageSync bool) (*runtimeHistory, error) {
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
		runtimeID:               runtimeID,
		logger:                  logging.GetLogger("runtime/history").With("runtime_id", runtimeID),
		ctx:                     ctx,
		cancelCtx:               cancelCtx,
		db:                      db,
		lastStorageSyncedRound:  roothash.RoundInvalid,
		honorStorageSync:        honorStorageSync,
		syncedBlocksNotifier:    pubsub.NewBroker(true),
		committedBlocksNotifier: pubsub.NewBroker(true),
		pruner:                  pruner,
		pruneCh:                 channels.NewRingChannel(1),
		initCh:                  make(chan struct{}),
		stopCh:                  make(chan struct{}),
		quitCh:                  make(chan struct{}),
	}

	go h.pruneWorker()

	return h, nil
}

// NewFactory creates a new runtime history keeper factory.
func NewFactory(prunerFactory PrunerFactory, honorStorageSync bool) Factory {
	return func(runtimeID common.Namespace, dataDir string) (History, error) {
		return New(runtimeID, dataDir, prunerFactory, honorStorageSync)
	}
}
