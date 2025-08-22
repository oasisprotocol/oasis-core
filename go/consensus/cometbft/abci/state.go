package abci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	proto "github.com/cosmos/gogoproto/proto"
	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	storageDB "github.com/oasisprotocol/oasis-core/go/storage/database"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var _ api.ApplicationState = (*applicationState)(nil)

// appStateDir is the subdirectory which contains ABCI state.
const appStateDir = "state"

type proposalState struct {
	// header is the partial proposal header (only set when we are the proposer).
	header *cmtproto.Header
	// txs is the set of proposed transactions (only set when we are the proposer).
	txs [][]byte
	// misbehavior is the set of proposed misbehavior evidence (only set when we are the proposer).
	misbehavior []types.Misbehavior

	// hash is the unique hash identifying this proposal. The hash is only available after the
	// proposal has been generated and is otherwise empty.
	hash []byte
	// tree is the state used for executing this proposal.
	tree mkvs.OverlayTree

	// resultsBeginBlock are the results of running the BeginBlock hook.
	resultsBeginBlock *types.ResponseBeginBlock
	// resultsDeliverTx are the results of executing DeliverTx for all transactions.
	resultsDeliverTx []*types.ResponseDeliverTx
	// resultsEndBlock are the results of running the EndBlock hook.
	resultsEndBlock *types.ResponseEndBlock
}

// isEqual returns true if the proposal is equal to the passed proposal.
func (ps *proposalState) isEqual(
	header *cmtproto.Header,
	txs [][]byte,
	misbehavior []types.Misbehavior,
) bool {
	if ps.header == nil {
		return false
	}
	if !bytes.Equal(header.ProposerAddress, ps.header.ProposerAddress) {
		return false
	}
	if len(txs) != len(ps.txs) {
		return false
	}
	if len(misbehavior) != len(ps.misbehavior) {
		return false
	}
	if !proto.Equal(header, ps.header) {
		return false
	}
	for i := range txs {
		if !bytes.Equal(txs[i], ps.txs[i]) {
			return false
		}
	}
	for i := range misbehavior {
		if !proto.Equal(&misbehavior[i], &ps.misbehavior[i]) {
			return false
		}
	}
	return true
}

// reset resets the proposal state.
func (ps *proposalState) reset() {
	ps.header = nil
	ps.txs = nil
	ps.misbehavior = nil
	ps.hash = nil
	ps.tree = nil
	ps.resultsBeginBlock = nil
	ps.resultsDeliverTx = nil
	ps.resultsEndBlock = nil
}

// needsExecution returns true iff the proposal has not yet been executed.
func (ps *proposalState) needsExecution() bool {
	return ps.resultsBeginBlock == nil || ps.resultsDeliverTx == nil || ps.resultsEndBlock == nil
}

// setResults sets the proposal execution results.
func (ps *proposalState) setResults(
	resultsBeginBlock *types.ResponseBeginBlock,
	resultsDeliverTx []*types.ResponseDeliverTx,
	resultsEndBlock *types.ResponseEndBlock,
) {
	ps.resultsBeginBlock = resultsBeginBlock
	ps.resultsDeliverTx = resultsDeliverTx
	ps.resultsEndBlock = resultsEndBlock
}

type applicationState struct {
	logger *logging.Logger

	ctx       context.Context
	cancelCtx context.CancelFunc

	initialHeight uint64

	stateRoot storage.Root
	storage   storage.LocalBackend

	// proposal is the working proposal state.
	proposal *proposalState

	// initState is the state that needs to be applied for chain initialization.
	initState mkvs.OverlayTree
	// initEvents are any events emitted during chain initialization.
	initEvents []types.Event
	// canonicalState is the current canonical state.
	canonicalState mkvs.Tree
	// checkState is the state snapshot from the last canonical state with any modifications from
	// transaction checks applied on top.
	checkState mkvs.Tree

	statePruner    StatePruner
	prunerClosedCh chan struct{}
	prunerNotifyCh *channels.RingChannel
	pruneInterval  time.Duration

	checkpointer checkpoint.Checkpointer
	upgrader     upgrade.Backend

	blockLock   sync.RWMutex
	blockTime   time.Time
	blockCtx    *api.BlockContext
	blockParams *consensusGenesis.Parameters

	txAuthHandler api.TransactionAuthHandler

	timeSource beacon.Backend

	haltEpoch  beacon.EpochTime
	haltHeight uint64

	minGasPrice        quantity.Quantity
	ownTxSigner        signature.PublicKey
	ownTxSignerAddress staking.Address
	identity           *identity.Identity

	metricsClosedCh chan struct{}
}

func (s *applicationState) NewContext(mode api.ContextMode) *api.Context {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	var (
		blockCtx *api.BlockContext
		state    mkvs.OverlayTree
	)
	lastHeight := int64(s.stateRoot.Version)
	now := s.blockTime
	switch mode {
	case api.ContextInitChain:
		if s.initState != nil {
			panic(fmt.Errorf("context: init state already set, re-entering InitChain?"))
		}
		s.initState = mkvs.NewOverlay(mkvs.New(nil, nil, storage.RootTypeState, mkvs.WithoutWriteLog()))
		state = s.initState
		// Configure block height so that current height will be correctly computed.
		lastHeight = int64(s.initialHeight) - 1
	case api.ContextCheckTx:
		state = mkvs.NewOverlayWrapper(s.checkState)
	case api.ContextDeliverTx, api.ContextBeginBlock, api.ContextEndBlock:
		state = s.proposal.tree
		blockCtx = s.blockCtx
		now = blockCtx.Time
	case api.ContextSimulateTx:
		// Since simulation is running in parallel to any changes to the database, we make sure
		// to create a separate in-memory tree at the given block height.
		state = mkvs.NewOverlayWrapper(mkvs.NewWithRoot(nil, s.storage.NodeDB(), s.stateRoot, mkvs.WithoutWriteLog()))
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
		blockCtx,
		lastHeight,
		int64(s.initialHeight),
	)
}

func (s *applicationState) LastRetainedVersion() (int64, error) {
	return int64(s.statePruner.GetLastRetainedVersion()), nil
}

func (s *applicationState) Storage() storage.LocalBackend {
	return s.storage
}

func (s *applicationState) Checkpointer() checkpoint.Checkpointer {
	return s.checkpointer
}

func (s *applicationState) InitialHeight() int64 {
	return int64(s.initialHeight)
}

func (s *applicationState) BlockHeight() int64 {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	height := s.stateRoot.Version
	if height < s.initialHeight {
		height = 0
	}
	return int64(height)
}

func (s *applicationState) StateRootHash() []byte {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	if s.stateRoot.Version < s.initialHeight {
		// CometBFT expects a nil hash when there is no state otherwise it will panic.
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

func (s *applicationState) GetBaseEpoch() (beacon.EpochTime, error) {
	return s.timeSource.GetBaseEpoch(s.ctx)
}

func (s *applicationState) GetEpoch(ctx context.Context, blockHeight int64) (beacon.EpochTime, error) {
	return s.timeSource.GetEpoch(ctx, blockHeight)
}

func (s *applicationState) GetCurrentEpoch(ctx context.Context) (beacon.EpochTime, error) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return beacon.EpochInvalid, nil
	}

	latestHeight := blockHeight
	if abciCtx := api.FromCtx(ctx); abciCtx != nil {
		// If request was made from an ABCI application context, then use blockHeight + 1, to fetch
		// the epoch at current (future) height. See cometbft/api.NewImmutableState for details.
		latestHeight++
	}

	// Check if there is an epoch transition scheduled for the current height. This should be taken
	// into account when GetCurrentEpoch is called before the time keeping app does the transition.
	future, err := s.timeSource.GetFutureEpoch(ctx, latestHeight)
	if err != nil {
		return beacon.EpochInvalid, fmt.Errorf("failed to get future epoch for height %d: %w", latestHeight, err)
	}
	if future != nil && future.Height == blockHeight+1 {
		return future.Epoch, nil
	}

	currentEpoch, err := s.timeSource.GetEpoch(ctx, latestHeight)
	if err != nil {
		return beacon.EpochInvalid, fmt.Errorf("failed to get epoch for height %d: %w", blockHeight+1, err)
	}
	return currentEpoch, nil
}

func (s *applicationState) EpochChanged(ctx *api.Context) (bool, beacon.EpochTime) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return false, beacon.EpochInvalid
	}
	latestHeight := blockHeight
	if abciCtx := api.FromCtx(ctx); abciCtx != nil {
		// If request was made from an ABCI application context, then use blockHeight + 1, to fetch
		// the epoch at current (future) height. See cometbft/api.NewImmutableState for details.
		latestHeight++
	}

	currentEpoch, err := s.timeSource.GetEpoch(ctx, latestHeight)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get current epoch",
			"err", err,
		)
		return false, beacon.EpochInvalid
	}

	if uint64(blockHeight) == s.initialHeight {
		// There is no block before the first block. For historic reasons, this is defined as not
		// having had a transition.
		return false, currentEpoch
	}

	previousEpoch, err := s.timeSource.GetEpoch(ctx, latestHeight-1)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get previous epoch",
			"err", err,
		)
		return false, beacon.EpochInvalid
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

func (s *applicationState) LocalMinGasPrice() *quantity.Quantity {
	return &s.minGasPrice
}

func (s *applicationState) OwnTxSigner() signature.PublicKey {
	return s.ownTxSigner
}

func (s *applicationState) OwnTxSignerAddress() staking.Address {
	return s.ownTxSignerAddress
}

func (s *applicationState) Upgrader() upgrade.Backend {
	return s.upgrader
}

func (s *applicationState) doInitChain() error {
	s.blockLock.Lock()
	defer s.blockLock.Unlock()

	// Preserve init state for possible rollbacks until the first block is committed.
	initStateCopy := s.initState.Copy(s.canonicalState)
	_, _ = initStateCopy.Commit(s.ctx) // Commit into s.canonicalState.

	// We use the height before the initial height for the state before the first block. Note that
	// this tree is not persisted, we only need it to compute the root hash.
	_, stateRootHash, err := s.canonicalState.Commit(s.ctx, s.stateRoot.Namespace, s.initialHeight-1, mkvs.NoPersist())
	if err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	s.stateRoot.Hash = stateRootHash
	s.stateRoot.Version = s.initialHeight - 1

	return s.doCommitOrInitChainLocked()
}

func (s *applicationState) doApplyStateSync(root storage.Root) error {
	s.blockLock.Lock()
	defer s.blockLock.Unlock()

	s.stateRoot = root

	s.canonicalState.Close()
	s.canonicalState = mkvs.NewWithRoot(nil, s.storage.NodeDB(), root, mkvs.WithoutWriteLog())
	s.checkState.Close()
	s.checkState = mkvs.NewWithRoot(nil, s.storage.NodeDB(), root, mkvs.WithoutWriteLog())

	return s.doCommitOrInitChainLocked()
}

func (s *applicationState) workingStateRoot() (hash.Hash, error) {
	// This is safe to do as we are operating on our own branch of state.
	psKv, err := s.proposal.tree.Commit(s.ctx)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("failed to commit: %w", err)
	}
	ps := psKv.(mkvs.Tree)
	// Only compute the root hash without persisting. In case this turns out to be the finalized
	// state, the root hash will not need to be recomputed again.
	_, stateRootHash, err := ps.Commit(s.ctx, s.stateRoot.Namespace, s.stateRoot.Version+1, mkvs.NoPersist())
	return stateRootHash, err
}

func (s *applicationState) doCommit() (uint64, error) {
	s.blockLock.Lock()
	defer s.blockLock.Unlock()

	// Clear init state after the first block is committed.
	if s.initState != nil {
		s.initState.Close()
		s.initState = nil
		s.initEvents = nil
	}

	// Last proposal state becomes the canonical state.
	canonicalState, err := s.proposal.tree.Commit(s.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to commit: %w", err)
	}
	s.canonicalState = canonicalState.(mkvs.Tree)
	s.proposal.reset()
	s.proposal = nil

	_, stateRootHash, err := s.canonicalState.Commit(s.ctx, s.stateRoot.Namespace, s.stateRoot.Version+1)
	if err != nil {
		return 0, fmt.Errorf("failed to commit: %w", err)
	}
	newStateRoot := storage.Root{
		Namespace: s.stateRoot.Namespace,
		Version:   s.stateRoot.Version + 1,
		Type:      storage.RootTypeState,
		Hash:      stateRootHash,
	}
	if err = s.storage.NodeDB().Finalize([]storage.Root{newStateRoot}); err != nil {
		return 0, fmt.Errorf("failed to finalize height %d: %w", newStateRoot.Version, err)
	}

	s.stateRoot.Hash = stateRootHash
	s.stateRoot.Version++

	if err := s.doCommitOrInitChainLocked(); err != nil {
		return 0, err
	}

	// Reset block context.
	s.blockCtx = nil
	// Switch the check tree to the newly committed version. Note that this is safe as CometBFT
	// holds the mempool lock while commit is in progress so no CheckTx can take place.
	s.checkState.Close()
	s.checkState = mkvs.NewWithRoot(nil, s.storage.NodeDB(), s.stateRoot, mkvs.WithoutWriteLog())

	// Notify pruner and checkpointer of a new block.
	s.prunerNotifyCh.In() <- s.stateRoot.Version
	// Discover the version below which all versions can be discarded from block history.
	lastRetainedVersion := s.statePruner.GetLastRetainedVersion()
	// Notify the checkpointer of the new version, if checkpointing is enabled.
	if s.checkpointer != nil {
		s.checkpointer.NotifyNewVersion(s.stateRoot.Version)
	}

	return lastRetainedVersion, nil
}

// Guarded by s.blockLock.
func (s *applicationState) doCommitOrInitChainLocked() error {
	s.blockTime = s.blockCtx.Time

	// Update cache of consensus parameters (the only places where consensus parameters can be
	// changed are InitChain and EndBlock, so we can safely update the cache here).
	state := consensusState.NewMutableState(s.canonicalState)
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

// resetProposal clears the current proposal state, replacing it with canonical state.
func (s *applicationState) resetProposal() {
	if s.proposal != nil {
		s.proposal.reset()
	}

	s.proposal = &proposalState{
		tree: mkvs.NewOverlay(s.canonicalState),
	}
	// (Temporarily) replace canonical state. Note that this version is only used in case the
	// proposal needs to be rolled back as otherwise the canonical state will be replaced with
	// the proposal state.
	if s.initState == nil {
		// Normal block processing.
		s.canonicalState = mkvs.NewWithRoot(nil, s.storage.NodeDB(), s.stateRoot, mkvs.WithoutWriteLog())
	} else {
		// When we have not yet processed the first block, we need to restore init state.
		s.canonicalState = mkvs.New(nil, s.storage.NodeDB(), storage.RootTypeState, mkvs.WithoutWriteLog())
		initStateCopy := s.initState.Copy(s.canonicalState)
		_, _ = initStateCopy.Commit(s.ctx) // Commit into s.canonicalState.
	}
}

// closeProposal clears the current proposal state and sets the current proposal to nil.
func (s *applicationState) closeProposal() {
	s.proposal.reset()
	s.proposal = nil
}

// resetProposalIfChanged checks whether the proposal has changed based on the passed hash and if it
// has clears the current proposal state, replacing it with canonical state.
//
// Returns true when the proposal has been reset.
func (s *applicationState) resetProposalIfChanged(h []byte) bool {
	if s.proposal != nil && bytes.Equal(s.proposal.hash, h) {
		return false
	}

	s.resetProposal()
	s.proposal.hash = h
	return true
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

func (s *applicationState) startPruner() error {
	go s.pruneWorker()
	return nil
}

func (s *applicationState) pruneWorker() {
	defer close(s.prunerClosedCh)

	s.logger.Debug("state pruner is starting")

	ticker := time.NewTicker(s.pruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("state pruner is terminating")
			return
		case <-ticker.C:
			var v any
			select {
			case v = <-s.prunerNotifyCh.Out():
			case <-s.ctx.Done():
				s.logger.Debug("state pruner is terminating")
				return
			}

			version := v.(uint64)

			if err := s.statePruner.Prune(version); err != nil {
				s.logger.Warn("failed to prune state",
					"err", err,
					"block_height", version,
				)
			}
		}
	}
}

// InitStateStorage initializes the internal ABCI state storage.
func InitStateStorage(cfg *ApplicationConfig) (storage.LocalBackend, storage.NodeDB, *storage.Root, error) {
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

	db, err := storageDB.New(&storage.Config{
		Backend:          cfg.StorageBackend,
		DB:               filepath.Join(baseDir, storageDB.DefaultFileName(cfg.StorageBackend)),
		MaxCacheSize:     64 * 1024 * 1024, // TODO: Make this configurable.
		DiscardWriteLogs: true,
		NoFsync:          true, // This is safe as CometBFT will replay on crash.
		MemoryOnly:       cfg.MemoryOnlyStorage,
		ReadOnly:         cfg.ReadOnlyStorage,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	ndb := db.NodeDB()

	// Make sure to close the database in case we fail.
	var ok bool
	defer func() {
		if !ok {
			db.Cleanup()
		}
	}()

	// Figure out the latest version/hash if any, and use that as the block height/hash.
	latestVersion, _ := ndb.GetLatestVersion()
	roots, err := ndb.GetRootsForVersion(latestVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	stateRoot := &storage.Root{
		Version: latestVersion,
		Type:    storage.RootTypeState,
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
		stateRoot.Hash = roots[0].Hash
	default:
		// More roots -- should not happen for our use case.
		return nil, nil, nil, fmt.Errorf("state: more than one root, corrupted database?")
	}

	ok = true

	return db, ndb, stateRoot, nil
}

func newApplicationState(ctx context.Context, upgrader upgrade.Backend, cfg *ApplicationConfig) (*applicationState, error) {
	if cfg.InitialHeight < 1 {
		return nil, fmt.Errorf("state: initial height must be >= 1 (got: %d)", cfg.InitialHeight)
	}

	// Initialize the state storage.
	ldb, ndb, stateRoot, err := InitStateStorage(cfg)
	if err != nil {
		return nil, err
	}
	latestVersion := stateRoot.Version

	// Use the node database directly to avoid going through the syncer interface.
	canonicalState := mkvs.NewWithRoot(nil, ndb, *stateRoot, mkvs.WithoutWriteLog())
	checkState := mkvs.NewWithRoot(nil, ndb, *stateRoot, mkvs.WithoutWriteLog())

	// Initialize the state pruner.
	statePruner, err := newStatePruner(&cfg.Pruning, ndb)
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
		initialHeight:      cfg.InitialHeight,
		canonicalState:     canonicalState,
		checkState:         checkState,
		stateRoot:          *stateRoot,
		storage:            ldb,
		statePruner:        statePruner,
		prunerClosedCh:     make(chan struct{}),
		prunerNotifyCh:     channels.NewRingChannel(1),
		pruneInterval:      cfg.Pruning.PruneInterval,
		upgrader:           upgrader,
		blockCtx:           api.NewBlockContext(api.BlockInfo{}),
		haltEpoch:          cfg.HaltEpoch,
		haltHeight:         cfg.HaltHeight,
		minGasPrice:        minGasPrice,
		ownTxSigner:        cfg.Identity.NodeSigner.Public(),
		ownTxSignerAddress: staking.NewAddress(cfg.Identity.NodeSigner.Public()),
		identity:           cfg.Identity,
		metricsClosedCh:    make(chan struct{}),
	}

	// Refresh consensus parameters when loading state if we are past genesis.
	if latestVersion >= s.initialHeight {
		if err = s.doCommitOrInitChainLocked(); err != nil {
			return nil, fmt.Errorf("state: failed to run initial state commit hook: %w", err)
		}
	}

	// Initialize the checkpointer.
	if !cfg.DisableCheckpointer {
		checkpointerCfg := checkpoint.CheckpointerConfig{
			Name:            "consensus",
			CheckInterval:   cfg.CheckpointerCheckInterval,
			RootsPerVersion: 1,
			GetParameters: func(_ context.Context) (*checkpoint.CreationParameters, error) {
				params := s.ConsensusParameters()
				return &checkpoint.CreationParameters{
					Interval:       params.StateCheckpointInterval,
					NumKept:        params.StateCheckpointNumKept,
					ChunkSize:      params.StateCheckpointChunkSize,
					InitialVersion: cfg.InitialHeight,
					ChunkerThreads: cfg.ChunkerThreads,
				}, nil
			},
		}
		s.checkpointer, err = checkpoint.NewCheckpointer(s.ctx, ndb, ldb.Checkpointer(), checkpointerCfg)
		if err != nil {
			return nil, fmt.Errorf("state: failed to create checkpointer: %w", err)
		}
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
