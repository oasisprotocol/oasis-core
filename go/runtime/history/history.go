// Package history implements the runtime block history and pruning policy.
package history

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// DbFilename is the filename of the history database.
const DbFilename = "history.db"

var (
	errNopHistory = errors.New("runtime/history: not supported")

	_ History = (*runtimeHistory)(nil)
)

// Config is runtime history keeper configuration.
type Config struct {
	// Pruner configures the pruner to use.
	Pruner PrunerFactory

	// PruneInterval configures the pruning interval.
	PruneInterval time.Duration
}

// NewDefaultConfig returns the default runtime history keeper config.
func NewDefaultConfig() *Config {
	return &Config{
		Pruner:        NewNonePruner(),
		PruneInterval: 10 * time.Second,
	}
}

// History is the runtime history interface.
type History interface {
	roothash.BlockHistory

	// Pruner returns the history pruner.
	Pruner() Pruner

	// Close closes the history keeper.
	Close()
}

type nopHistory struct {
	runtimeID common.Namespace
}

func (h *nopHistory) RuntimeID() common.Namespace {
	return h.runtimeID
}

func (h *nopHistory) Commit(blk *roothash.AnnotatedBlock, roundResults *roothash.RoundResults, notify bool) error {
	return errNopHistory
}

func (h *nopHistory) ConsensusCheckpoint(height int64) error {
	return errNopHistory
}

func (h *nopHistory) StorageSyncCheckpoint(ctx context.Context, round uint64) error {
	return errNopHistory
}

func (h *nopHistory) LastStorageSyncedRound() (uint64, error) {
	return 0, errNopHistory
}

func (h *nopHistory) WatchBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	return nil, nil, errNopHistory
}

func (h *nopHistory) WaitRoundSynced(ctx context.Context, round uint64) (uint64, error) {
	return 0, errNopHistory
}

func (h *nopHistory) LastConsensusHeight() (int64, error) {
	return 0, errNopHistory
}

func (h *nopHistory) GetCommittedBlock(ctx context.Context, round uint64) (*block.Block, error) {
	return nil, errNopHistory
}

func (h *nopHistory) GetBlock(ctx context.Context, round uint64) (*block.Block, error) {
	return nil, errNopHistory
}

func (h *nopHistory) GetAnnotatedBlock(ctx context.Context, round uint64) (*roothash.AnnotatedBlock, error) {
	return nil, errNopHistory
}

func (h *nopHistory) GetEarliestBlock(ctx context.Context) (*block.Block, error) {
	return nil, errNopHistory
}

func (h *nopHistory) GetRoundResults(ctx context.Context, round uint64) (*roothash.RoundResults, error) {
	return nil, errNopHistory
}

func (h *nopHistory) Pruner() Pruner {
	pruner, _ := NewNonePruner()(nil)
	return pruner
}

func (h *nopHistory) Close() {
}

// NewNop creates a new no-op runtime history keeper.
func NewNop(runtimeID common.Namespace) History {
	return &nopHistory{runtimeID: runtimeID}
}

type runtimeHistory struct {
	runtimeID common.Namespace

	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc

	db             *DB
	blocksNotifier *pubsub.Broker

	// Last storage synced round as reported by the storage backend (if enabled).
	syncRoundLock          sync.RWMutex
	lastStorageSyncedRound uint64

	haveLocalStorageWorker bool

	pruner        Pruner
	pruneInterval time.Duration
	pruneCh       *channels.RingChannel
	stopCh        chan struct{}
	quitCh        chan struct{}
}

func (h *runtimeHistory) RuntimeID() common.Namespace {
	return h.runtimeID
}

func (h *runtimeHistory) Commit(blk *roothash.AnnotatedBlock, roundResults *roothash.RoundResults, notify bool) error {
	err := h.db.commit(blk, roundResults)
	if err != nil {
		return err
	}

	// Notify the pruner what the new round is.
	h.pruneCh.In() <- blk.Block.Header.Round

	// If no local storage worker, notify the block watcher that new block is committed,
	// otherwise the storage-sync-checkpoint will do the notification.
	if h.haveLocalStorageWorker || !notify {
		return nil
	}
	h.blocksNotifier.Broadcast(blk)

	return nil
}

func (h *runtimeHistory) ConsensusCheckpoint(height int64) error {
	return h.db.consensusCheckpoint(height)
}

func (h *runtimeHistory) StorageSyncCheckpoint(ctx context.Context, round uint64) error {
	if !h.haveLocalStorageWorker {
		panic("received storage sync checkpoint when local storage worker is disabled")
	}

	h.syncRoundLock.Lock()
	defer h.syncRoundLock.Unlock()
	switch {
	case round < h.lastStorageSyncedRound:
		return fmt.Errorf("runtime/history: storage sync checkpoint at lower height (current: %d wanted: %d)", h.lastStorageSyncedRound, round)
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
	h.blocksNotifier.Broadcast(annBlk)

	return nil
}

func (h *runtimeHistory) LastStorageSyncedRound() (uint64, error) {
	h.syncRoundLock.RLock()
	defer h.syncRoundLock.RUnlock()
	return h.lastStorageSyncedRound, nil
}

func (h *runtimeHistory) WatchBlocks() (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *roothash.AnnotatedBlock)
	sub := h.blocksNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
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
			return roothash.RoundInvalid, err
		}
		h.syncRoundLock.RLock()
		defer h.syncRoundLock.RUnlock()
		// Also take storage sync state into account.
		if includeStorage && h.haveLocalStorageWorker && h.lastStorageSyncedRound < meta.LastRound {
			return h.lastStorageSyncedRound, nil
		}
		return meta.LastRound, nil
	default:
		h.syncRoundLock.RLock()
		defer h.syncRoundLock.RUnlock()
		// Ensure round exists.
		if includeStorage && h.haveLocalStorageWorker && h.lastStorageSyncedRound < round {
			return roothash.RoundInvalid, roothash.ErrNotFound
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

func (h *runtimeHistory) GetRoundResults(ctx context.Context, round uint64) (*roothash.RoundResults, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	resolvedRound, err := h.resolveRound(round, true)
	if err != nil {
		return nil, err
	}
	return h.db.getRoundResults(resolvedRound)
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

	ticker := time.NewTicker(h.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var round interface{}
			select {
			case round = <-h.pruneCh.Out():
			case <-h.stopCh:
				h.logger.Info("prune worker is terminating")
				return
			}

			h.logger.Debug("pruning runtime history",
				"round", round.(uint64),
			)

			if err := h.pruner.Prune(h.ctx, round.(uint64)); err != nil {
				h.logger.Error("failed to prune",
					"err", err,
				)
				continue
			}
		case <-h.stopCh:
			h.logger.Info("prune worker is terminating")
			return
		}
	}
}

// New creates a new runtime history keeper.
func New(dataDir string, runtimeID common.Namespace, cfg *Config, haveLocalStorageWorker bool) (History, error) {
	db, err := newDB(filepath.Join(dataDir, DbFilename), runtimeID)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = NewDefaultConfig()
	}
	if cfg.Pruner == nil {
		cfg.Pruner = NewNonePruner()
	}
	pruner, err := cfg.Pruner(db)
	if err != nil {
		return nil, err
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	h := &runtimeHistory{
		runtimeID:              runtimeID,
		logger:                 logging.GetLogger("roothash/history").With("runtime_id", runtimeID),
		ctx:                    ctx,
		cancelCtx:              cancelCtx,
		db:                     db,
		haveLocalStorageWorker: haveLocalStorageWorker,
		blocksNotifier:         pubsub.NewBroker(true),
		pruner:                 pruner,
		pruneInterval:          cfg.PruneInterval,
		pruneCh:                channels.NewRingChannel(1),
		stopCh:                 make(chan struct{}),
		quitCh:                 make(chan struct{}),
	}
	go h.pruneWorker()

	return h, nil
}
