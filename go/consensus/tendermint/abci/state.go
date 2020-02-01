package abci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/db"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

var (
	// ErrNoState is the error returned when state is nil.
	ErrNoState = errors.New("tendermint: no state available (app not registered?)")

	_ ApplicationState = (*applicationState)(nil)
	_ ApplicationState = (*mockApplicationState)(nil)
)

// ApplicationState is the overall past, present and future state of all multiplexed applications.
type ApplicationState interface {
	// BlockHeight returns the last committed block height.
	BlockHeight() int64

	// BlockHash returns the last committed block hash.
	BlockHash() []byte

	// BlockContext returns the current block context which can be used
	// to store intermediate per-block results.
	//
	// This method must only be called from BeginBlock/DeliverTx/EndBlock
	// and calls from anywhere else will cause races.
	BlockContext() *BlockContext

	// DeliverTxTree returns the versioned tree to be used by queries
	// to view comitted data, and transactions to build the next version.
	DeliverTxTree() *iavl.MutableTree

	// CheckTxTree returns the state tree to be used for modifications
	// inside CheckTx (mempool connection) calls.
	//
	// This state is never persisted.
	CheckTxTree() *iavl.MutableTree

	// GetBaseEpoch returns the base epoch.
	GetBaseEpoch() (epochtime.EpochTime, error)

	// GetEpoch returns epoch at block height.
	GetEpoch(ctx context.Context, blockHeight int64) (epochtime.EpochTime, error)

	// GetCurrentEpoch returns the epoch at the current block height.
	GetCurrentEpoch(ctx context.Context) (epochtime.EpochTime, error)

	// EpochChanged returns true iff the current epoch has changed since the
	// last block.  As a matter of convenience, the current epoch is returned.
	EpochChanged(ctx *Context) (bool, epochtime.EpochTime)

	// Genesis returns the ABCI genesis state.
	Genesis() *genesis.Document

	// MinGasPrice returns the configured minimum gas price.
	MinGasPrice() *quantity.Quantity

	// OwnTxSigner returns the transaction signer identity of the local node.
	OwnTxSigner() signature.PublicKey

	// NewContext creates a new application processing context.
	NewContext(mode ContextMode, now time.Time) *Context
}

type applicationState struct {
	logger *logging.Logger

	ctx           context.Context
	db            dbm.DB
	deliverTxTree *iavl.MutableTree
	checkTxTree   *iavl.MutableTree
	statePruner   StatePruner

	blockLock   sync.RWMutex
	blockHash   []byte
	blockHeight int64
	blockTime   time.Time
	blockCtx    *BlockContext

	txAuthHandler TransactionAuthHandler

	timeSource epochtime.Backend

	haltMode        bool
	haltEpochHeight epochtime.EpochTime

	minGasPrice quantity.Quantity
	ownTxSigner signature.PublicKey

	metricsCloseCh  chan struct{}
	metricsClosedCh chan struct{}
}

func (s *applicationState) NewContext(mode ContextMode, now time.Time) *Context {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	c := &Context{
		mode:          mode,
		currentTime:   now,
		gasAccountant: NewNopGasAccountant(),
		appState:      s,
		blockHeight:   s.blockHeight,
		logger:        logging.GetLogger("consensus/tendermint/abci").With("mode", mode),
	}
	c.ctx = context.WithValue(s.ctx, contextKey{}, c)

	switch mode {
	case ContextInitChain:
		c.state = s.deliverTxTree
	case ContextCheckTx:
		c.state = s.checkTxTree
	case ContextDeliverTx, ContextBeginBlock, ContextEndBlock:
		c.state = s.deliverTxTree
		c.blockCtx = s.blockCtx
	case ContextSimulateTx:
		// Since simulation is running in parallel to any changes to the database, we make sure
		// to create a separate in-memory tree at the given block height.
		c.state = iavl.NewMutableTree(s.db, 128)
		// NOTE: This requires a specific implementation of `LoadVersion` which doesn't rely
		//       on cached metadata. Such an implementation is provided in our fork of IAVL.
		if _, err := c.state.LoadVersion(c.blockHeight); err != nil {
			panic(fmt.Errorf("context: failed to load state at height %d: %w", c.blockHeight, err))
		}
		c.currentTime = s.blockTime
	default:
		panic(fmt.Errorf("context: invalid mode: %s (%d)", mode, mode))
	}

	return c
}

// BlockHeight returns the last committed block height.
func (s *applicationState) BlockHeight() int64 {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return s.blockHeight
}

// BlockHash returns the last committed block hash.
func (s *applicationState) BlockHash() []byte {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return append([]byte{}, s.blockHash...)
}

// BlockContext returns the current block context which can be used
// to store intermediate per-block results.
//
// This method must only be called from BeginBlock/DeliverTx/EndBlock
// and calls from anywhere else will cause races.
func (s *applicationState) BlockContext() *BlockContext {
	return s.blockCtx
}

// DeliverTxTree returns the versioned tree to be used by queries
// to view comitted data, and transactions to build the next version.
func (s *applicationState) DeliverTxTree() *iavl.MutableTree {
	return s.deliverTxTree
}

// CheckTxTree returns the state tree to be used for modifications
// inside CheckTx (mempool connection) calls.
//
// This state is never persisted.
func (s *applicationState) CheckTxTree() *iavl.MutableTree {
	return s.checkTxTree
}

// GetBaseEpoch returns the base epoch.
func (s *applicationState) GetBaseEpoch() (epochtime.EpochTime, error) {
	return s.timeSource.GetBaseEpoch(s.ctx)
}

// GetEpoch returns epoch at block height.
func (s *applicationState) GetEpoch(ctx context.Context, blockHeight int64) (epochtime.EpochTime, error) {
	return s.timeSource.GetEpoch(ctx, blockHeight)
}

// GetCurrentEpoch returns the epoch at the current block height.
func (s *applicationState) GetCurrentEpoch(ctx context.Context) (epochtime.EpochTime, error) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return epochtime.EpochInvalid, nil
	}
	currentEpoch, err := s.timeSource.GetEpoch(ctx, blockHeight+1)
	if err != nil {
		return epochtime.EpochInvalid, fmt.Errorf("application state time source get epoch for height %d: %w", blockHeight+1, err)
	}
	return currentEpoch, nil
}

// EpochChanged returns true iff the current epoch has changed since the
// last block.  As a matter of convenience, the current epoch is returned.
func (s *applicationState) EpochChanged(ctx *Context) (bool, epochtime.EpochTime) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return false, epochtime.EpochInvalid
	}

	currentEpoch, err := s.timeSource.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get current epoch",
			"err", err,
		)
		return false, epochtime.EpochInvalid
	}

	if blockHeight == 1 {
		// There is no block before the first block. For historic reasons, this is defined as not
		// having had a transition.
		return false, currentEpoch
	}

	previousEpoch, err := s.timeSource.GetEpoch(ctx.Ctx(), blockHeight)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get previous epoch",
			"err", err,
		)
		return false, epochtime.EpochInvalid
	}

	if previousEpoch == currentEpoch {
		return false, currentEpoch
	}

	s.logger.Debug("EpochChanged: epoch transition detected",
		"prev_epoch", previousEpoch,
		"epoch", currentEpoch,
	)

	return true, currentEpoch
}

// Genesis returns the ABCI genesis state.
func (s *applicationState) Genesis() *genesis.Document {
	_, b := s.checkTxTree.Get([]byte(stateKeyGenesisRequest))

	var req types.RequestInitChain
	if err := req.Unmarshal(b); err != nil {
		s.logger.Error("Genesis: corrupted defered genesis state",
			"err", err,
		)
		panic("Genesis: invalid defered genesis application state")
	}

	st, err := parseGenesisAppState(req)
	if err != nil {
		s.logger.Error("failed to unmarshal genesis application state",
			"err", err,
			"state", req.AppStateBytes,
		)
		panic("Genesis: invalid genesis application state")
	}

	return st
}

// MinGasPrice returns the configured minimum gas price.
func (s *applicationState) MinGasPrice() *quantity.Quantity {
	return &s.minGasPrice
}

// OwnTxSigner returns the transaction signer identity of the local node.
func (s *applicationState) OwnTxSigner() signature.PublicKey {
	return s.ownTxSigner
}

func (s *applicationState) inHaltEpoch(ctx *Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("inHaltEpoch: failed to get epoch",
			"err", err,
			"block_height", blockHeight+1,
		)
		return false
	}
	s.haltMode = currentEpoch == s.haltEpochHeight
	return s.haltMode
}

func (s *applicationState) afterHaltEpoch(ctx *Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("afterHaltEpoch: failed to get epoch",
			"err", err,
			"block_height", blockHeight,
		)
		return false
	}

	return currentEpoch > s.haltEpochHeight
}

func (s *applicationState) doCommit(now time.Time) error {
	// Save the new version of the persistent tree.
	blockHash, blockHeight, err := s.deliverTxTree.SaveVersion()
	if err == nil {
		s.blockLock.Lock()
		s.blockHash = blockHash
		s.blockHeight = blockHeight
		s.blockTime = now
		s.blockLock.Unlock()

		// Reset CheckTx state to latest version. This is safe because
		// Tendermint holds a lock on the mempool for commit.
		//
		// WARNING: deliverTxTree and checkTxTree do not share internal
		// state beyond the backing database.  The `LoadVersion`
		// implementation MUST be written in a way to avoid relying on
		// cached metadata.
		//
		// This makes the upstream `LazyLoadVersion` and `LoadVersion`
		// unsuitable for our use case.
		_, cerr := s.checkTxTree.LoadVersion(blockHeight)
		if cerr != nil {
			panic(cerr)
		}

		// Prune the iavl state according to the specified strategy.
		s.statePruner.Prune(s.blockHeight)
	}

	return err
}

func (s *applicationState) doCleanup() {
	if s.db != nil {
		// Don't close the DB out from under the metrics worker.
		close(s.metricsCloseCh)
		<-s.metricsClosedCh

		s.db.Close()
		s.db = nil
	}
}

func (s *applicationState) updateMetrics() error {
	var dbSize int64

	switch m := s.db.(type) {
	case api.SizeableDB:
		var err error
		if dbSize, err = m.Size(); err != nil {
			s.logger.Error("Size",
				"err", err,
			)
			return err
		}
	default:
		return fmt.Errorf("state: unsupported DB for metrics")
	}

	abciSize.Set(float64(dbSize) / 1024768.0)

	return nil
}

func (s *applicationState) metricsWorker() {
	defer close(s.metricsClosedCh)

	// Update the metrics once on initialization.
	if err := s.updateMetrics(); err != nil {
		// If this fails, don't bother trying again, it's most likely
		// an unsupported DB backend.
		s.logger.Warn("metrics not available",
			"err", err,
		)
		return
	}

	t := time.NewTicker(metricsUpdateInterval)
	defer t.Stop()

	for {
		select {
		case <-s.metricsCloseCh:
			return
		case <-t.C:
			_ = s.updateMetrics()
		}
	}
}

func newApplicationState(ctx context.Context, cfg *ApplicationConfig) (*applicationState, error) {
	db, err := db.New(filepath.Join(cfg.DataDir, "abci-mux-state"), false)
	if err != nil {
		return nil, err
	}

	// Figure out the latest version/hash if any, and use that
	// as the block height/hash.
	deliverTxTree := iavl.NewMutableTree(db, 128)
	blockHeight, err := deliverTxTree.Load()
	if err != nil {
		db.Close()
		return nil, err
	}
	blockHash := deliverTxTree.Hash()

	checkTxTree := iavl.NewMutableTree(db, 128)
	checkTxBlockHeight, err := checkTxTree.Load()
	if err != nil {
		db.Close()
		return nil, err
	}

	if blockHeight != checkTxBlockHeight || !bytes.Equal(blockHash, checkTxTree.Hash()) {
		db.Close()
		return nil, fmt.Errorf("state: inconsistent trees")
	}

	statePruner, err := newStatePruner(&cfg.Pruning, deliverTxTree, blockHeight)
	if err != nil {
		db.Close()
		return nil, err
	}

	var minGasPrice quantity.Quantity
	if err = minGasPrice.FromInt64(int64(cfg.MinGasPrice)); err != nil {
		return nil, fmt.Errorf("state: invalid minimum gas price: %w", err)
	}

	s := &applicationState{
		logger:          logging.GetLogger("abci-mux/state"),
		ctx:             ctx,
		db:              db,
		deliverTxTree:   deliverTxTree,
		checkTxTree:     checkTxTree,
		statePruner:     statePruner,
		blockHash:       blockHash,
		blockHeight:     blockHeight,
		haltEpochHeight: cfg.HaltEpochHeight,
		minGasPrice:     minGasPrice,
		ownTxSigner:     cfg.OwnTxSigner,
		metricsCloseCh:  make(chan struct{}),
		metricsClosedCh: make(chan struct{}),
	}
	go s.metricsWorker()

	return s, nil
}

func parseGenesisAppState(req types.RequestInitChain) (*genesis.Document, error) {
	var st genesis.Document
	if err := json.Unmarshal(req.AppStateBytes, &st); err != nil {
		return nil, err
	}

	return &st, nil
}

// MockApplicationStateConfig is the configuration for the mock application state.
type MockApplicationStateConfig struct {
	BlockHeight int64
	BlockHash   []byte

	BaseEpoch    epochtime.EpochTime
	CurrentEpoch epochtime.EpochTime
	EpochChanged bool

	MaxBlockGas transaction.Gas
	MinGasPrice *quantity.Quantity

	OwnTxSigner signature.PublicKey

	Genesis *genesis.Document
}

type mockApplicationState struct {
	cfg MockApplicationStateConfig

	blockCtx *BlockContext
	tree     *iavl.MutableTree
}

func (ms *mockApplicationState) BlockHeight() int64 {
	return ms.cfg.BlockHeight
}

func (ms *mockApplicationState) BlockHash() []byte {
	return ms.cfg.BlockHash
}

func (ms *mockApplicationState) BlockContext() *BlockContext {
	return ms.blockCtx
}

func (ms *mockApplicationState) DeliverTxTree() *iavl.MutableTree {
	return ms.tree
}

func (ms *mockApplicationState) CheckTxTree() *iavl.MutableTree {
	return ms.tree
}

func (ms *mockApplicationState) GetBaseEpoch() (epochtime.EpochTime, error) {
	return ms.cfg.BaseEpoch, nil
}

func (ms *mockApplicationState) GetEpoch(ctx context.Context, blockHeight int64) (epochtime.EpochTime, error) {
	return ms.cfg.CurrentEpoch, nil
}

func (ms *mockApplicationState) GetCurrentEpoch(ctx context.Context) (epochtime.EpochTime, error) {
	return ms.cfg.CurrentEpoch, nil
}

func (ms *mockApplicationState) EpochChanged(ctx *Context) (bool, epochtime.EpochTime) {
	return ms.cfg.EpochChanged, ms.cfg.CurrentEpoch
}

func (ms *mockApplicationState) Genesis() *genesis.Document {
	return ms.cfg.Genesis
}

func (ms *mockApplicationState) MinGasPrice() *quantity.Quantity {
	return ms.cfg.MinGasPrice
}

func (ms *mockApplicationState) OwnTxSigner() signature.PublicKey {
	return ms.cfg.OwnTxSigner
}

func (ms *mockApplicationState) NewContext(mode ContextMode, now time.Time) *Context {
	c := &Context{
		mode:          mode,
		currentTime:   now,
		gasAccountant: NewNopGasAccountant(),
		state:         ms.tree,
		appState:      ms,
		blockHeight:   ms.cfg.BlockHeight,
		blockCtx:      ms.blockCtx,
		logger:        logging.GetLogger("consensus/tendermint/abci").With("mode", mode),
	}
	c.ctx = context.WithValue(context.Background(), contextKey{}, c)

	return c
}

// NewMockApplicationState creates a new mock application state for testing.
func NewMockApplicationState(cfg MockApplicationStateConfig) ApplicationState {
	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)

	blockCtx := NewBlockContext()
	if cfg.MaxBlockGas > 0 {
		blockCtx.Set(GasAccountantKey{}, NewGasAccountant(cfg.MaxBlockGas))
	} else {
		blockCtx.Set(GasAccountantKey{}, NewNopGasAccountant())
	}

	return &mockApplicationState{
		cfg:      cfg,
		blockCtx: blockCtx,
		tree:     tree,
	}
}

// ImmutableState is an immutable state wrapper.
type ImmutableState struct {
	// Snapshot is the backing immutable iAVL tree snapshot.
	Snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable state wrapper.
func NewImmutableState(state ApplicationState, version int64) (*ImmutableState, error) {
	if state == nil {
		return nil, ErrNoState
	}
	if state.BlockHeight() == 0 {
		return nil, consensus.ErrNoCommittedBlocks
	}
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	snapshot, err := state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{Snapshot: snapshot}, nil
}
