package abci

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	abciState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	storageDB "github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var _ api.ApplicationState = (*applicationState)(nil)

// appStateDir is the subdirectory which contains ABCI state.
const appStateDir = "abci-state"

type applicationState struct { // nolint: maligned
	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc

	stateRoot     storage.Root
	storage       storage.LocalBackend
	deliverTxTree mkvs.Tree
	checkTxTree   mkvs.Tree

	statePruner    StatePruner
	prunerClosedCh chan struct{}
	prunerNotifyCh *channels.RingChannel

	blockLock   sync.RWMutex
	blockTime   time.Time
	blockCtx    *api.BlockContext
	blockParams *consensusGenesis.Parameters

	txAuthHandler TransactionAuthHandler

	timeSource epochtime.Backend

	haltMode        bool
	haltEpochHeight epochtime.EpochTime

	minGasPrice        quantity.Quantity
	ownTxSigner        signature.PublicKey
	ownTxSignerAddress staking.Address
	disableCheckTx     bool

	metricsClosedCh chan struct{}
}

func (s *applicationState) NewContext(mode api.ContextMode, now time.Time) *api.Context {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	var blockCtx *api.BlockContext
	var state mkvs.Tree
	switch mode {
	case api.ContextInitChain:
		state = s.deliverTxTree
	case api.ContextCheckTx:
		state = s.checkTxTree
	case api.ContextDeliverTx, api.ContextBeginBlock, api.ContextEndBlock:
		state = s.deliverTxTree
		blockCtx = s.blockCtx
	case api.ContextSimulateTx:
		// Since simulation is running in parallel to any changes to the database, we make sure
		// to create a separate in-memory tree at the given block height.
		state = mkvs.NewWithRoot(nil, s.storage.NodeDB(), s.stateRoot, mkvs.WithoutWriteLog())
		now = s.blockTime
	default:
		panic(fmt.Errorf("context: invalid mode: %s (%d)", mode, mode))
	}

	return api.NewContext(
		s.ctx,
		mode,
		now,
		api.NewNopGasAccountant(),
		s,
		state,
		int64(s.stateRoot.Version),
		blockCtx,
	)
}

func (s *applicationState) Storage() storage.LocalBackend {
	return s.storage
}

func (s *applicationState) BlockHeight() int64 {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return int64(s.stateRoot.Version)
}

func (s *applicationState) BlockHash() []byte {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	if s.stateRoot.Version == 0 {
		// Tendermint expects a nil hash when there is no state otherwise it will panic.
		return nil
	}
	return s.stateRoot.Hash[:]
}

func (s *applicationState) ConsensusParameters() *consensusGenesis.Parameters {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return s.blockParams
}

func (s *applicationState) BlockContext() *api.BlockContext {
	return s.blockCtx
}

func (s *applicationState) GetBaseEpoch() (epochtime.EpochTime, error) {
	return s.timeSource.GetBaseEpoch(s.ctx)
}

func (s *applicationState) GetEpoch(ctx context.Context, blockHeight int64) (epochtime.EpochTime, error) {
	return s.timeSource.GetEpoch(ctx, blockHeight)
}

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

func (s *applicationState) EpochChanged(ctx *api.Context) (bool, epochtime.EpochTime) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return false, epochtime.EpochInvalid
	}

	currentEpoch, err := s.timeSource.GetEpoch(ctx, blockHeight+1)
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

	previousEpoch, err := s.timeSource.GetEpoch(ctx, blockHeight)
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

func (s *applicationState) MinGasPrice() *quantity.Quantity {
	return &s.minGasPrice
}

func (s *applicationState) OwnTxSigner() signature.PublicKey {
	return s.ownTxSigner
}

func (s *applicationState) OwnTxSignerAddress() staking.Address {
	return s.ownTxSignerAddress
}

func (s *applicationState) inHaltEpoch(ctx *api.Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx, blockHeight+1)
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

func (s *applicationState) afterHaltEpoch(ctx *api.Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx, blockHeight+1)
	if err != nil {
		s.logger.Error("afterHaltEpoch: failed to get epoch",
			"err", err,
			"block_height", blockHeight,
		)
		return false
	}

	return currentEpoch > s.haltEpochHeight
}

func (s *applicationState) doInitChain(now time.Time) error {
	s.blockLock.Lock()
	defer s.blockLock.Unlock()

	return s.doCommitOrInitChainLocked(now)
}

func (s *applicationState) doCommit(now time.Time) (uint64, error) {
	s.blockLock.Lock()
	defer s.blockLock.Unlock()

	_, stateRootHash, err := s.deliverTxTree.Commit(s.ctx, s.stateRoot.Namespace, s.stateRoot.Version+1)
	if err != nil {
		return 0, fmt.Errorf("failed to commit: %w", err)
	}
	if err = s.storage.NodeDB().Finalize(s.ctx, s.stateRoot.Version+1, []hash.Hash{stateRootHash}); err != nil {
		return 0, fmt.Errorf("failed to finalize round %d: %w", s.stateRoot.Version+1, err)
	}

	s.stateRoot.Hash = stateRootHash
	s.stateRoot.Version++

	if err := s.doCommitOrInitChainLocked(now); err != nil {
		return 0, err
	}

	// Switch the CheckTx tree to the newly committed version. Note that this is safe as Tendermint
	// holds the mempool lock while commit is in progress so no CheckTx can take place.
	s.checkTxTree.Close()
	s.checkTxTree = mkvs.NewWithRoot(nil, s.storage.NodeDB(), s.stateRoot, mkvs.WithoutWriteLog())

	// Notify pruner of a new block.
	s.prunerNotifyCh.In() <- s.stateRoot.Version
	// Discover the version below which all versions can be discarded from block history.
	lastRetainedVersion := s.statePruner.GetLastRetainedVersion()

	return lastRetainedVersion, nil
}

// Guarded by s.blockLock.
func (s *applicationState) doCommitOrInitChainLocked(now time.Time) error {
	s.blockTime = now

	// Update cache of consensus parameters (the only places where consensus parameters can be
	// changed are InitChain and EndBlock, so we can safely update the cache here).
	state := abciState.NewMutableState(s.deliverTxTree)
	params, err := state.ConsensusParameters(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to load consensus parameters: %w", err)
	}
	s.blockParams = params

	return nil
}

func (s *applicationState) doCleanup() {
	if s.storage != nil {
		// Don't close the DB out from under the metrics/pruner worker.
		s.cancelCtx()
		<-s.prunerClosedCh
		<-s.metricsClosedCh

		s.storage.Cleanup()
		s.storage = nil
	}
}

func (s *applicationState) updateMetrics() error {
	var dbSize int64
	var err error
	if dbSize, err = s.storage.NodeDB().Size(); err != nil {
		s.logger.Error("Size",
			"err", err,
		)
		return err
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
		case <-s.ctx.Done():
			return
		case <-t.C:
			_ = s.updateMetrics()
		}
	}
}

func (s *applicationState) pruneWorker() {
	defer close(s.prunerClosedCh)

	for {
		select {
		case <-s.ctx.Done():
			return
		case r := <-s.prunerNotifyCh.Out():
			round := r.(uint64)

			if err := s.statePruner.Prune(s.ctx, round); err != nil {
				s.logger.Warn("failed to prune state",
					"err", err,
					"block_height", round,
				)
			}
		}
	}
}

// InitStateStorage initializes the internal ABCI state storage.
func InitStateStorage(ctx context.Context, cfg *ApplicationConfig) (storage.LocalBackend, storage.NodeDB, *storage.Root, error) {
	baseDir := filepath.Join(cfg.DataDir, appStateDir)
	switch cfg.ReadOnlyStorage {
	case true:
		// Note: I'm not sure what badger does when given a path that
		// doesn't actually contain a database, when it's set to
		// read-only.  Hopefully it's something sensible.
		fi, err := os.Lstat(baseDir)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to stat application state directory: %w", err)
		}
		if !fi.Mode().IsDir() {
			return nil, nil, nil, fmt.Errorf("application state path is not a directory: %v", fi.Mode())
		}
	default:
		if err := common.Mkdir(baseDir); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create application state directory: %w", err)
		}
	}

	switch cfg.StorageBackend {
	case storageDB.BackendNameBadgerDB:
	default:
		return nil, nil, nil, fmt.Errorf("unsupported storage backend: %s", cfg.StorageBackend)
	}

	db, err := storageDB.New(&storage.Config{
		Backend:          cfg.StorageBackend,
		DB:               filepath.Join(baseDir, storageDB.DefaultFileName(cfg.StorageBackend)),
		MaxCacheSize:     64 * 1024 * 1024, // TODO: Make this configurable.
		DiscardWriteLogs: true,
		NoFsync:          true, // This is safe as Tendermint will replay on crash.
		MemoryOnly:       cfg.MemoryOnlyStorage,
		ReadOnly:         cfg.ReadOnlyStorage,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	ldb := db.(storage.LocalBackend)
	ndb := ldb.NodeDB()

	// Make sure to close the database in case we fail.
	var ok bool
	defer func() {
		if !ok {
			db.Cleanup()
		}
	}()

	// Figure out the latest version/hash if any, and use that as the block height/hash.
	latestVersion, err := ndb.GetLatestVersion(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := ndb.GetRootsForVersion(ctx, latestVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	stateRoot := &storage.Root{
		Version: latestVersion,
	}
	switch len(roots) {
	case 0:
		// No roots -- empty database.
		if latestVersion != 0 {
			return nil, nil, nil, fmt.Errorf("state: no roots at non-zero height, corrupted database?")
		}
		stateRoot.Hash.Empty()
	case 1:
		// Exactly one root -- the usual case.
		stateRoot.Hash = roots[0]
	default:
		// More roots -- should not happen for our use case.
		return nil, nil, nil, fmt.Errorf("state: more than one root, corrupted database?")
	}

	ok = true

	return ldb, ndb, stateRoot, nil
}

func newApplicationState(ctx context.Context, cfg *ApplicationConfig) (*applicationState, error) {
	// Initialize the state storage.
	ldb, ndb, stateRoot, err := InitStateStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	latestVersion := stateRoot.Version

	// Use the node database directly to avoid going through the syncer interface.
	deliverTxTree := mkvs.NewWithRoot(nil, ndb, *stateRoot, mkvs.WithoutWriteLog())
	checkTxTree := mkvs.NewWithRoot(nil, ndb, *stateRoot, mkvs.WithoutWriteLog())

	// Initialize the state pruner.
	statePruner, err := newStatePruner(&cfg.Pruning, ndb, latestVersion)
	if err != nil {
		return nil, fmt.Errorf("state: failed to create pruner: %w", err)
	}

	var minGasPrice quantity.Quantity
	if err = minGasPrice.FromInt64(int64(cfg.MinGasPrice)); err != nil {
		return nil, fmt.Errorf("state: invalid minimum gas price: %w", err)
	}

	ctx, cancelCtx := context.WithCancel(ctx)

	s := &applicationState{
		logger:             logging.GetLogger("abci-mux/state"),
		ctx:                ctx,
		cancelCtx:          cancelCtx,
		deliverTxTree:      deliverTxTree,
		checkTxTree:        checkTxTree,
		stateRoot:          *stateRoot,
		storage:            ldb,
		statePruner:        statePruner,
		prunerClosedCh:     make(chan struct{}),
		prunerNotifyCh:     channels.NewRingChannel(1),
		haltEpochHeight:    cfg.HaltEpochHeight,
		minGasPrice:        minGasPrice,
		ownTxSigner:        cfg.OwnTxSigner,
		ownTxSignerAddress: staking.NewAddress(cfg.OwnTxSigner),
		disableCheckTx:     cfg.DisableCheckTx,
		metricsClosedCh:    make(chan struct{}),
	}

	// Refresh consensus parameters when loading state if we are past genesis.
	if latestVersion > 0 {
		if err = s.doCommitOrInitChainLocked(time.Time{}); err != nil {
			return nil, fmt.Errorf("state: failed to run initial state commit hook: %w", err)
		}
	}

	go s.metricsWorker()
	go s.pruneWorker()

	return s, nil
}

func parseGenesisAppState(req types.RequestInitChain) (*genesis.Document, error) {
	var st genesis.Document
	if err := json.Unmarshal(req.AppStateBytes, &st); err != nil {
		return nil, err
	}

	return &st, nil
}
