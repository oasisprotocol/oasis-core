// Package statesync defines the logic responsible for initializing, syncing,
// and pruning of the runtime state using the relevant p2p protocol clients.
package statesync

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	commonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registryApi "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/diffsync"
	storagePub "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/pub"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

var (
	_ committee.NodeHooks = (*Worker)(nil)

	// ErrNonLocalBackend is the error returned when the storage backend doesn't implement the LocalBackend interface.
	ErrNonLocalBackend = errors.New("storage: storage backend doesn't support local storage")
)

const (
	// RoundLatest is a magic value for the latest round.
	RoundLatest = math.MaxUint64

	defaultUndefinedRound = ^uint64(0)

	checkpointSyncRetryDelay = 10 * time.Second

	// The maximum number of rounds the worker can be behind the chain before it's sensible for
	// it to register as available.
	maximumRoundDelayForAvailability = uint64(10)

	// The minimum number of rounds the worker can be behind the chain before it's sensible for
	// it to stop advertising availability.
	minimumRoundDelayForUnavailability = uint64(15)

	// chunkerThreads is target number of subtrees during parallel checkpoint creation.
	// It is intentionally non-configurable since we want operators to produce
	// same checkpoint hashes. The current value was chosen based on the benchmarks
	// done on the modern developer machine.
	chunkerThreads = 12
)

// Worker is the runtime state sync worker, responsible for syncing state
// that corresponds to the incoming runtime block headers received from the
// consensus service.
//
// In addition this worker is responsible for:
//  1. Initializing the runtime state, possibly using checkpoints (if configured).
//  2. Pruning the state as specified by the configuration.
//  3. Optionally creating runtime state checkpoints (used by other nodes) for the state sync.
//  4. Creating (and optionally advertising) statesync p2p protocol clients and servers.
//  5. Registering node availability when it has synced sufficiently close to
//     the latest known block header.
//
// Suggestion: This worker should not be responsible for creating and advertising p2p related stuff.
// Instead it should receive the p2p client (even better interface) for fetching storage diffs and checkpoints.
type Worker struct { // nolint: maligned
	commonNode *committee.Node

	roleProvider    registration.RoleProvider
	rpcRoleProvider registration.RoleProvider
	roleAvailable   bool

	logger *logging.Logger

	localStorage storageApi.LocalBackend

	diffSync          diffsync.Client
	checkpointSync    checkpointsync.Client
	legacyStorageSync synclegacy.Client

	undefinedRound uint64

	workerCommonCfg workerCommon.Config

	checkpointer         checkpoint.Checkpointer
	checkpointSyncCfg    *CheckpointSyncConfig
	checkpointSyncForced bool

	syncedLock  sync.RWMutex
	syncedState blockSummary

	statusLock sync.RWMutex
	status     api.StorageWorkerStatus

	blockCh *channels.InfiniteChannel

	initCh chan struct{}
}

// New creates a new state sync worker.
func New(
	ctx context.Context,
	commonNode *committee.Node,
	roleProvider registration.RoleProvider,
	rpcRoleProvider registration.RoleProvider,
	workerCommonCfg workerCommon.Config,
	localStorage storageApi.LocalBackend,
	checkpointSyncCfg *CheckpointSyncConfig,
) (*Worker, error) {
	initMetrics()

	w := &Worker{
		commonNode: commonNode,

		roleProvider:    roleProvider,
		rpcRoleProvider: rpcRoleProvider,

		logger: logging.GetLogger("worker/storage/statesync").With("runtime_id", commonNode.Runtime.ID()),

		workerCommonCfg: workerCommonCfg,

		localStorage: localStorage,

		checkpointSyncCfg: checkpointSyncCfg,

		status: api.StatusInitializing,

		blockCh: channels.NewInfiniteChannel(),

		initCh: make(chan struct{}),
	}

	// Validate checkpoint sync configuration.
	if err := checkpointSyncCfg.Validate(); err != nil {
		return nil, fmt.Errorf("bad checkpoint sync configuration: %w", err)
	}

	// Initialize sync state.
	w.syncedState.Round = defaultUndefinedRound

	// Create a checkpointer (even if checkpointing is disabled) to ensure the genesis checkpoint is available.
	checkpointer, err := w.newCheckpointer(ctx, commonNode, localStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkpointer: %w", err)
	}
	w.checkpointer = checkpointer

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{
		logger: w.logger,
		worker: w,
	})

	// Advertise and serve p2p protocols.
	commonNode.P2P.RegisterProtocolServer(synclegacy.NewServer(commonNode.ChainContext, commonNode.Runtime.ID(), localStorage))
	commonNode.P2P.RegisterProtocolServer(diffsync.NewServer(commonNode.ChainContext, commonNode.Runtime.ID(), localStorage))
	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		commonNode.P2P.RegisterProtocolServer(checkpointsync.NewServer(commonNode.ChainContext, commonNode.Runtime.ID(), localStorage))
	}
	if rpcRoleProvider != nil {
		commonNode.P2P.RegisterProtocolServer(storagePub.NewServer(commonNode.ChainContext, commonNode.Runtime.ID(), localStorage))
	}

	// Create p2p protocol clients.
	w.legacyStorageSync = synclegacy.NewClient(commonNode.P2P, commonNode.ChainContext, commonNode.Runtime.ID())
	w.diffSync = diffsync.NewClient(commonNode.P2P, commonNode.ChainContext, commonNode.Runtime.ID())
	w.checkpointSync = checkpointsync.NewClient(commonNode.P2P, commonNode.ChainContext, commonNode.Runtime.ID())

	return w, nil
}

// Initialized returns a channel that will be closed once the worker finished starting up.
func (w *Worker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetStatus returns the state sync worker status.
func (w *Worker) GetStatus(context.Context) (*api.Status, error) {
	w.syncedLock.RLock()
	defer w.syncedLock.RUnlock()

	w.statusLock.RLock()
	defer w.statusLock.RUnlock()

	return &api.Status{
		LastFinalizedRound: w.syncedState.Round,
		Status:             w.status,
	}, nil
}

func (w *Worker) PauseCheckpointer(pause bool) error {
	if !commonFlags.DebugDontBlameOasis() {
		return api.ErrCantPauseCheckpointer
	}
	w.checkpointer.Pause(pause)
	return nil
}

// GetLocalStorage returns the local storage backend used by this state sync worker.
func (w *Worker) GetLocalStorage() storageApi.LocalBackend {
	return w.localStorage
}

// NodeHooks implementation.

// HandleNewBlockEarlyLocked is guarded by CrossNode.
func (w *Worker) HandleNewBlockEarlyLocked(*runtime.BlockInfo) {
	// Nothing to do here.
}

// HandleNewBlockLocked is guarded by CrossNode.
func (w *Worker) HandleNewBlockLocked(bi *runtime.BlockInfo) {
	// Notify the state syncer that there is a new block.
	w.blockCh.In() <- bi.RuntimeBlock
}

// HandleRuntimeHostEventLocked is guarded by CrossNode.
func (w *Worker) HandleRuntimeHostEventLocked(*host.Event) {
	// Nothing to do here.
}

// Watcher implementation.

// GetLastSynced returns the height, IORoot hash and StateRoot hash of the last block that was fully synced to.
func (w *Worker) GetLastSynced() (uint64, storageApi.Root, storageApi.Root) {
	w.syncedLock.RLock()
	defer w.syncedLock.RUnlock()

	var io, state storageApi.Root
	for _, root := range w.syncedState.Roots {
		switch root.Type {
		case storageApi.RootTypeIO:
			io = root
		case storageApi.RootTypeState:
			state = root
		}
	}

	return w.syncedState.Round, io, state
}

// Run runs state sync worker.
func (w *Worker) Run(ctx context.Context) error { // nolint: gocyclo
	// Wait for the common node to be initialized.
	select {
	case <-w.commonNode.Initialized():
	case <-ctx.Done():
		close(w.initCh)
		return ctx.Err()
	}

	w.logger.Info("starting runtime state sync worker")

	w.statusLock.Lock()
	w.status = api.StatusStarting
	w.statusLock.Unlock()

	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		go w.createCheckpoints(ctx)
	}

	// Determine genesis block.
	genesisBlock, err := w.commonNode.Consensus.RootHash().GetGenesisBlock(ctx, &roothashApi.RuntimeRequest{
		RuntimeID: w.commonNode.Runtime.ID(),
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		return fmt.Errorf("can't retrieve genesis block: %w", err)
	}
	w.undefinedRound = genesisBlock.Header.Round - 1

	// Determine last finalized storage version.
	if version, dbNonEmpty := w.localStorage.NodeDB().GetLatestVersion(); dbNonEmpty {
		var blk *block.Block
		blk, err = w.commonNode.Runtime.History().GetCommittedBlock(ctx, version)
		switch err {
		case nil:
			// Set last synced version to last finalized storage version.
			if _, err = w.flushSyncedState(summaryFromBlock(blk)); err != nil {
				return fmt.Errorf("failed to flush synced state: %w", err)
			}
		default:
			// Failed to fetch historic block. This is fine when the network just went through a
			// dump/restore upgrade and we don't have any information before genesis. We treat the
			// database as unsynced and will proceed to either use checkpoints or sync iteratively.
			w.logger.Warn("failed to fetch historic block",
				"err", err,
				"round", version,
			)
		}
	}

	w.syncedLock.RLock()
	cachedLastRound := w.syncedState.Round
	w.syncedLock.RUnlock()
	if cachedLastRound == defaultUndefinedRound || cachedLastRound < genesisBlock.Header.Round {
		cachedLastRound = w.undefinedRound
	}

	// Initialize genesis from the runtime descriptor.
	isInitialStartup := (cachedLastRound == w.undefinedRound)
	if isInitialStartup {
		w.statusLock.Lock()
		w.status = api.StatusInitializingGenesis
		w.statusLock.Unlock()

		var rt *registryApi.Runtime
		rt, err = w.commonNode.Runtime.ActiveDescriptor(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve runtime registry descriptor: %w", err)
		}
		if err = w.initGenesis(ctx, rt, genesisBlock); err != nil {
			return fmt.Errorf("failed to initialize storage at genesis: %w", err)
		}
	}

	// Notify the checkpointer of the genesis round so it can be checkpointed.
	if w.checkpointer != nil {
		w.checkpointer.ForceCheckpoint(genesisBlock.Header.Round)
		w.checkpointer.Flush()
	}

	// Check if we are able to fetch the first block that we would be syncing if we used iterative
	// syncing. In case we cannot (likely because we synced the consensus layer via state sync), we
	// must wait for a later checkpoint to become available.
	if !w.checkpointSyncForced {
		w.statusLock.Lock()
		w.status = api.StatusSyncStartCheck
		w.statusLock.Unlock()

		// Determine what is the first round that we would need to sync.
		iterativeSyncStart := cachedLastRound
		if iterativeSyncStart == w.undefinedRound {
			iterativeSyncStart++
		}

		// Check if we actually have information about that round. This assumes that any reindexing
		// was already performed (the common node would not indicate being initialized otherwise).
		_, err = w.commonNode.Runtime.History().GetCommittedBlock(ctx, iterativeSyncStart)
	SyncStartCheck:
		switch {
		case err == nil:
		case errors.Is(err, roothashApi.ErrNotFound):
			// No information is available about the initial round. Query the earliest historic
			// block and check if that block has the genesis state root and empty I/O root.
			var earlyBlk *block.Block
			earlyBlk, err = w.commonNode.Runtime.History().GetEarliestBlock(ctx)
			switch err {
			case nil:
				// Make sure the state root is still the same as at genesis time.
				if !earlyBlk.Header.StateRoot.Equal(&genesisBlock.Header.StateRoot) {
					break
				}
				// Make sure the I/O root is empty.
				if !earlyBlk.Header.IORoot.IsEmpty() {
					break
				}

				// If this is the case, we can start syncing from this round instead. Fill in the
				// remaining versions to make sure they actually exist in the database.
				w.logger.Debug("filling in versions to genesis",
					"genesis_round", genesisBlock.Header.Round,
					"earliest_round", earlyBlk.Header.Round,
				)
				for v := genesisBlock.Header.Round; v < earlyBlk.Header.Round; v++ {
					err = w.localStorage.Apply(ctx, &storageApi.ApplyRequest{
						Namespace: w.commonNode.Runtime.ID(),
						RootType:  storageApi.RootTypeState,
						SrcRound:  v,
						SrcRoot:   genesisBlock.Header.StateRoot,
						DstRound:  v + 1,
						DstRoot:   genesisBlock.Header.StateRoot,
						WriteLog:  nil, // No changes.
					})
					switch err {
					case nil:
					case storageApi.ErrAlreadyFinalized:
						// Ignore already finalized versions.
						continue
					default:
						return fmt.Errorf("failed to fill in version %d: %w", v, err)
					}

					err = w.localStorage.NodeDB().Finalize([]storageApi.Root{{
						Namespace: w.commonNode.Runtime.ID(),
						Version:   v + 1,
						Type:      storageApi.RootTypeState,
						Hash:      genesisBlock.Header.StateRoot,
						// We can ignore I/O roots.
					}})
					if err != nil {
						return fmt.Errorf("failed to finalize filled in version %v: %w", v, err)
					}
				}
				cachedLastRound, err = w.flushSyncedState(summaryFromBlock(earlyBlk))
				if err != nil {
					return fmt.Errorf("failed to flush synced state: %w", err)
				}
				// No need to force a checkpoint sync.
				break SyncStartCheck
			default:
				// This should never happen as the block should exist.
				w.logger.Warn("failed to query earliest block in local history",
					"err", err,
				)
			}

			// No information is available about this round, force checkpoint sync.
			w.logger.Warn("forcing checkpoint sync as we don't have authoritative block info",
				"round", iterativeSyncStart,
			)
			w.checkpointSyncForced = true
		default:
			// Unknown error while fetching block information, abort.
			return fmt.Errorf("failed to query block: %w", err)
		}
	}

	w.logger.Info("worker initialized",
		"genesis_round", genesisBlock.Header.Round,
		"last_synced", cachedLastRound,
	)

	// Try to perform initial sync from state and io checkpoints if either:
	//
	// - Checkpoint sync has been forced because there is insufficient information available to use
	//   incremental sync.
	//
	// - We haven't synced anything yet and checkpoint sync is not disabled.
	//
	// If checkpoint sync is disabled but sync has been forced (e.g. because the state at genesis
	// is non-empty), we must request to sync the checkpoint at genesis as otherwise we will jump
	// to a later state which may not be desired given that checkpoint sync has been explicitly
	// disabled via config.
	//
	if (isInitialStartup && !w.checkpointSyncCfg.Disabled) || w.checkpointSyncForced {
		w.statusLock.Lock()
		w.status = api.StatusSyncingCheckpoints
		w.statusLock.Unlock()

		var (
			summary *blockSummary
			attempt int
		)
	CheckpointSyncRetry:
		for {
			summary, err = w.syncCheckpoints(ctx, genesisBlock.Header.Round, w.checkpointSyncCfg.Disabled)
			if err == nil {
				break
			}

			attempt++
			switch w.checkpointSyncForced {
			case true:
				// We have no other options but to perform a checkpoint sync as we are missing
				// either state or authoritative blocks.
				w.logger.Info("checkpoint sync required, retrying",
					"err", err,
					"attempt", attempt,
				)
			case false:
				if attempt > 1 {
					break CheckpointSyncRetry
				}

				// Try syncing again. The main reason for this is the sync failing due to a
				// checkpoint pruning race condition (where nodes list a checkpoint which is
				// then deleted just before we request its chunks). One retry is enough.
				w.logger.Info("first checkpoint sync failed, trying once more", "err", err)
			}

			// Delay before retrying.
			select {
			case <-time.After(checkpointSyncRetryDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err != nil {
			w.logger.Info("checkpoint sync failed", "err", err)
		} else {
			cachedLastRound, err = w.flushSyncedState(summary)
			if err != nil {
				return fmt.Errorf("failed to flush synced state %w", err)
			}
			w.logger.Info("checkpoint sync succeeded",
				logging.LogEvent, LogEventCheckpointSyncSuccess,
			)
		}
	}
	close(w.initCh)

	w.statusLock.Lock()
	w.status = api.StatusSyncingRounds
	w.statusLock.Unlock()

	return w.sync(ctx, cachedLastRound, config.GlobalConfig.Storage.FetcherCount)
}

func (w *Worker) sync(ctx context.Context, lastFinalizedRound uint64, fetcherCount uint) error {
	blkCh := make(chan *block.Block)

	diffSyncer := newDiffSyncer(w.commonNode.Runtime.ID(), w.localStorage, w.commonNode.Runtime.History(), w, w.undefinedRound)
	syncerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	syncerDone := make(chan error)
	go func() {
		select {
		case <-ctx.Done():
			return
		case syncerDone <- diffSyncer.sync(syncerCtx, blkCh, lastFinalizedRound, fetcherCount):
		}
	}()

	finalizedCh, sub, err := diffSyncer.watchFinalizedSummaries()
	if err != nil {
		return fmt.Errorf("failed to subcribe to diff syncer finalizations: %w", err)
	}
	defer sub.Close()

	// Don't register availability immediately, we want to know first how far behind consensus we are.
	latestBlockRound := w.undefinedRound
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-syncerDone:
			if err != nil {
				return fmt.Errorf("Syncer stopped with error: %w", err)
			}
			return nil
		case inBlk := <-w.blockCh.Out():
			blk := inBlk.(*block.Block)
			w.logger.Debug("incoming block",
				"round", blk.Header.Round,
				"last_finalized", lastFinalizedRound,
			)
			latestBlockRound = blk.Header.Round
			// Fixme: If block channel has many pending blocks (e.g. after checkpoint sync),
			// nudgeAvailability may incorrectly set the node as available too early.
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)
			select { // TODO annoying that you duplicate this part.
			case <-ctx.Done():
				return ctx.Err()
			case err := <-syncerDone:
				if err != nil {
					return fmt.Errorf("Syncer stopped with error: %w", err)
				}
				return nil
			case blkCh <- blk:
			}
		case finalized := <-finalizedCh:
			var err error
			lastFinalizedRound, err = w.flushSyncedState(finalized)
			if err != nil { // Suggestion: DB operations can always fail, consider retrying.
				return fmt.Errorf("failed to flush synced state: %w", err)
			}

			// Check if we're far enough to reasonably register as available.
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)

			// Notify the checkpointer that there is a new finalized round.
			if config.GlobalConfig.Storage.Checkpointer.Enabled {
				w.checkpointer.NotifyNewVersion(finalized.Round)
			}
		}
	}
}

func (w *Worker) flushSyncedState(summary *blockSummary) (uint64, error) {
	w.syncedLock.Lock()
	defer w.syncedLock.Unlock()

	w.syncedState = *summary
	if err := w.commonNode.Runtime.History().StorageSyncCheckpoint(w.syncedState.Round); err != nil {
		return 0, err
	}

	return w.syncedState.Round, nil
}

func (w *Worker) initGenesis(ctx context.Context, rt *registryApi.Runtime, genesisBlock *block.Block) error {
	w.logger.Info("initializing storage at genesis")

	// Check what the latest finalized version in the database is as we may be using a database
	// from a previous version or network.
	latestVersion, alreadyInitialized := w.localStorage.NodeDB().GetLatestVersion()

	// Finalize any versions that were not yet finalized in the old database. This is only possible
	// as long as there is only one non-finalized root per version. Note that we also cannot be sure
	// that any of these roots are valid, but this is fine as long as the final version matches the
	// genesis root.
	if alreadyInitialized {
		w.logger.Debug("already initialized, finalizing any non-finalized versions",
			"genesis_state_root", genesisBlock.Header.StateRoot,
			"genesis_round", genesisBlock.Header.Round,
			"latest_version", latestVersion,
		)

		for v := latestVersion + 1; v < genesisBlock.Header.Round; v++ {
			roots, err := w.localStorage.NodeDB().GetRootsForVersion(v)
			if err != nil {
				return fmt.Errorf("failed to fetch roots for version %d: %w", v, err)
			}

			var stateRoots []storageApi.Root
			for _, root := range roots {
				if root.Type == storageApi.RootTypeState {
					stateRoots = append(stateRoots, root)
				}
			}
			if len(stateRoots) != 1 {
				break // We must have exactly one non-finalized state root to continue.
			}

			err = w.localStorage.NodeDB().Finalize(stateRoots)
			if err != nil {
				return fmt.Errorf("failed to finalize version %d: %w", v, err)
			}

			latestVersion = v
		}
	}

	stateRoot := storageApi.Root{
		Namespace: rt.ID,
		Version:   genesisBlock.Header.Round,
		Type:      storageApi.RootTypeState,
		Hash:      genesisBlock.Header.StateRoot,
	}

	var compatible bool
	switch {
	case latestVersion < stateRoot.Version:
		// Latest version is earlier than the genesis state root. In case it has the same hash
		// we can fill in all the missing versions.
		maybeRoot := stateRoot
		maybeRoot.Version = latestVersion

		if w.localStorage.NodeDB().HasRoot(maybeRoot) {
			w.logger.Debug("latest version earlier than genesis state root, filling in versions",
				"genesis_state_root", genesisBlock.Header.StateRoot,
				"genesis_round", genesisBlock.Header.Round,
				"latest_version", latestVersion,
			)
			for v := latestVersion; v < stateRoot.Version; v++ {
				err := w.localStorage.Apply(ctx, &storageApi.ApplyRequest{
					Namespace: rt.ID,
					RootType:  storageApi.RootTypeState,
					SrcRound:  v,
					SrcRoot:   stateRoot.Hash,
					DstRound:  v + 1,
					DstRoot:   stateRoot.Hash,
					WriteLog:  nil, // No changes.
				})
				if err != nil {
					return fmt.Errorf("failed to fill in version %d: %w", v, err)
				}

				err = w.localStorage.NodeDB().Finalize([]storageApi.Root{{
					Namespace: rt.ID,
					Version:   v + 1,
					Type:      storageApi.RootTypeState,
					Hash:      stateRoot.Hash,
					// We can ignore I/O roots.
				}})
				if err != nil {
					return fmt.Errorf("failed to finalize version %d: %w", v, err)
				}
			}
			compatible = true
		}
	default:
		// Latest finalized version is the same or ahead, root must exist.
		compatible = w.localStorage.NodeDB().HasRoot(stateRoot)
	}

	// If we are incompatible and the local version is greater or the same as the genesis version,
	// we cannot do anything. If the local version is lower we assume the node will sync from a
	// different node.
	if !compatible && latestVersion >= stateRoot.Version {
		w.logger.Error("existing state is incompatible with runtime genesis state",
			"genesis_state_root", genesisBlock.Header.StateRoot,
			"genesis_round", genesisBlock.Header.Round,
			"latest_version", latestVersion,
		)
		return fmt.Errorf("existing state is incompatible with runtime genesis state")
	}

	if !compatible {
		// Database is empty, so assume the state will be replicated from another node.
		w.logger.Warn("non-empty state root but no state available, assuming replication",
			"state_root", genesisBlock.Header.StateRoot,
		)
		w.checkpointSyncForced = true
	}
	return nil
}

// This is only called from the main worker goroutine, so no locking should be necessary.
func (w *Worker) nudgeAvailability(lastSynced, latest uint64) {
	if lastSynced == w.undefinedRound || latest == w.undefinedRound {
		return
	}
	if latest-lastSynced < maximumRoundDelayForAvailability && !w.roleAvailable {
		w.roleProvider.SetAvailable(func(_ *node.Node) error {
			return nil
		})
		if w.rpcRoleProvider != nil {
			w.rpcRoleProvider.SetAvailable(func(_ *node.Node) error {
				return nil
			})
		}
		w.roleAvailable = true
	}
	if latest-lastSynced > minimumRoundDelayForUnavailability && w.roleAvailable {
		w.roleProvider.SetUnavailable()
		if w.rpcRoleProvider != nil {
			w.rpcRoleProvider.SetUnavailable()
		}
		w.roleAvailable = false
	}
}

// fetchDiff fetches writelog using diff sync p2p protocol client.
//
// The request relies on the default timeout of the underlying p2p protocol clients.
//
// In case of no peers or error, it fallbacks to the legacy storage sync protocol.
func (w *Worker) fetchDiff(ctx context.Context, prevRoot, thisRoot storageApi.Root) (storageApi.WriteLog, rpc.PeerFeedback, error) {
	rsp1, pf, err := w.diffSync.GetDiff(ctx, &diffsync.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err == nil { // if NO error
		return rsp1.WriteLog, pf, nil
	}

	rsp2, pf, err := w.legacyStorageSync.GetDiff(ctx, &synclegacy.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err != nil {
		return nil, nil, err
	}
	return rsp2.WriteLog, pf, nil
}
