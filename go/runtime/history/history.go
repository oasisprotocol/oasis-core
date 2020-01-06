// Package history implements the runtime block history and pruning policy.
package history

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/eapache/channels"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
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

func (h *nopHistory) Commit(blk *roothash.AnnotatedBlock) error {
	return errNopHistory
}

func (h *nopHistory) ConsensusCheckpoint(height int64) error {
	return errNopHistory
}

func (h *nopHistory) LastConsensusHeight() (int64, error) {
	return 0, errNopHistory
}

func (h *nopHistory) GetBlock(ctx context.Context, round uint64) (*block.Block, error) {
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

	db *DB

	pruner        Pruner
	pruneInterval time.Duration
	pruneCh       *channels.RingChannel
	stopCh        chan struct{}
	quitCh        chan struct{}
}

func (h *runtimeHistory) RuntimeID() common.Namespace {
	return h.runtimeID
}

func (h *runtimeHistory) Commit(blk *roothash.AnnotatedBlock) error {
	err := h.db.commit(blk)
	if err != nil {
		return err
	}

	// Notify the pruner what the new round is.
	h.pruneCh.In() <- blk.Block.Header.Round

	return nil
}

func (h *runtimeHistory) ConsensusCheckpoint(height int64) error {
	return h.db.consensusCheckpoint(height)
}

func (h *runtimeHistory) LastConsensusHeight() (int64, error) {
	meta, err := h.db.metadata()
	if err != nil {
		return 0, err
	}

	return meta.LastConsensusHeight, nil
}

func (h *runtimeHistory) GetBlock(ctx context.Context, round uint64) (*block.Block, error) {
	annBlk, err := h.db.getBlock(round)
	if err != nil {
		return nil, err
	}

	return annBlk.Block, nil
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
func New(dataDir string, runtimeID common.Namespace, cfg *Config) (History, error) {
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
		runtimeID:     runtimeID,
		logger:        logging.GetLogger("roothash/history").With("runtime_id", runtimeID),
		ctx:           ctx,
		cancelCtx:     cancelCtx,
		db:            db,
		pruner:        pruner,
		pruneInterval: cfg.PruneInterval,
		pruneCh:       channels.NewRingChannel(1),
		stopCh:        make(chan struct{}),
		quitCh:        make(chan struct{}),
	}
	go h.pruneWorker()

	return h, nil
}
