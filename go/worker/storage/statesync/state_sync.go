// Package statesync defines the logic responsible for initializing, syncing,
// and pruning of the runtime state using the relevant p2p protocol clients.
package statesync

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	commonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registryApi "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/diffsync"
	storagePub "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/pub"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

// ErrNonLocalBackend is the error returned when the storage backend doesn't implement the LocalBackend interface.
var ErrNonLocalBackend = errors.New("storage: storage backend doesn't support local storage")

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

	// maxInFlightRounds is the maximum number of rounds that should be fetched before waiting
	// for them to be applied.
	maxInFlightRounds = 100

	// chunkerThreads is target number of subtrees during parallel checkpoint creation.
	// It is intentionally non-configurable since we want operators to produce
	// same checkpoint hashes. The current value was chosen based on the benchmarks
	// done on the modern developer machine.
	chunkerThreads = 12

	// diffResponseTimeout is the maximum time for fetching storage diff from the peer.
	diffResponseTimeout = 15 * time.Second
)

type roundItem interface {
	GetRound() uint64
}

// minRoundQueue is a Round()-based min priority queue.
type minRoundQueue []roundItem

// Sorting interface.
func (q minRoundQueue) Len() int           { return len(q) }
func (q minRoundQueue) Less(i, j int) bool { return q[i].GetRound() < q[j].GetRound() }
func (q minRoundQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *minRoundQueue) Push(x any) {
	*q = append(*q, x.(roundItem))
}

// Pop removes and returns the last element in the heap's array.
func (q *minRoundQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// fetchedDiff has all the context needed for a single GetDiff operation.
type fetchedDiff struct {
	fetched  bool
	pf       rpc.PeerFeedback
	err      error
	round    uint64
	prevRoot storageApi.Root
	thisRoot storageApi.Root
	writeLog storageApi.WriteLog
}

func (d *fetchedDiff) GetRound() uint64 {
	return d.round
}

type finalizeResult struct {
	summary *blockSummary
	err     error
}

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
type Worker struct {
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

	checkpointer         checkpoint.Checkpointer
	checkpointSyncCfg    *CheckpointSyncConfig
	checkpointSyncForced bool

	syncedLock  sync.RWMutex
	syncedState blockSummary

	statusLock sync.RWMutex
	status     api.StorageWorkerStatus

	blockCh    *channels.InfiniteChannel
	diffCh     chan *fetchedDiff
	finalizeCh chan finalizeResult

	initCh chan struct{}
}

// New creates a new state sync worker.
func New(
	commonNode *committee.Node,
	roleProvider registration.RoleProvider,
	rpcRoleProvider registration.RoleProvider,
	localStorage storageApi.LocalBackend,
	blockCh *channels.InfiniteChannel,
	checkpointSyncCfg *CheckpointSyncConfig,
) (*Worker, error) {
	initMetrics()

	w := &Worker{
		commonNode: commonNode,

		roleProvider:    roleProvider,
		rpcRoleProvider: rpcRoleProvider,

		logger: logging.GetLogger("worker/storage/statesync").With("runtime_id", commonNode.Runtime.ID()),

		localStorage: localStorage,

		checkpointSyncCfg: checkpointSyncCfg,

		status: api.StatusInitializing,

		blockCh:    blockCh,
		diffCh:     make(chan *fetchedDiff),
		finalizeCh: make(chan finalizeResult),

		initCh: make(chan struct{}),
	}

	// Validate checkpoint sync configuration.
	if err := checkpointSyncCfg.Validate(); err != nil {
		return nil, fmt.Errorf("bad checkpoint sync configuration: %w", err)
	}

	// Initialize sync state.
	w.syncedState.Round = defaultUndefinedRound

	// Create a checkpointer (even if checkpointing is disabled) to ensure the genesis checkpoint is available.
	checkpointer, err := w.newCheckpointer(commonNode, localStorage)
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

func (w *Worker) newCheckpointer(commonNode *committee.Node, localStorage storageApi.LocalBackend) (checkpoint.Checkpointer, error) {
	checkInterval := checkpoint.CheckIntervalDisabled
	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		checkInterval = config.GlobalConfig.Storage.Checkpointer.CheckInterval
	}
	checkpointerCfg := checkpoint.CheckpointerConfig{
		Name:            "runtime",
		Namespace:       commonNode.Runtime.ID(),
		CheckInterval:   checkInterval,
		RootsPerVersion: 2, // State root and I/O root.
		GetParameters: func(ctx context.Context) (*checkpoint.CreationParameters, error) {
			rt, rerr := commonNode.Runtime.ActiveDescriptor(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("failed to retrieve runtime descriptor: %w", rerr)
			}

			blk, rerr := commonNode.Consensus.RootHash().GetGenesisBlock(ctx, &roothashApi.RuntimeRequest{
				RuntimeID: rt.ID,
				Height:    consensus.HeightLatest,
			})
			if rerr != nil {
				return nil, fmt.Errorf("failed to retrieve genesis block: %w", rerr)
			}

			var threads uint16
			if config.GlobalConfig.Storage.Checkpointer.ParallelChunker {
				threads = chunkerThreads
			}

			return &checkpoint.CreationParameters{
				Interval:       rt.Storage.CheckpointInterval,
				NumKept:        rt.Storage.CheckpointNumKept,
				ChunkSize:      rt.Storage.CheckpointChunkSize,
				InitialVersion: blk.Header.Round,
				ChunkerThreads: threads,
			}, nil
		},
		GetRoots: func(ctx context.Context, version uint64) ([]storageApi.Root, error) {
			blk, berr := commonNode.Runtime.History().GetCommittedBlock(ctx, version)
			if berr != nil {
				return nil, berr
			}

			return blk.Header.StorageRoots(), nil
		},
	}

	return checkpoint.NewCheckpointer(
		localStorage.NodeDB(),
		localStorage.Checkpointer(),
		checkpointerCfg,
	), nil
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

func (w *Worker) fetchDiff(ctx context.Context, round uint64, prevRoot, thisRoot storageApi.Root) {
	result := &fetchedDiff{
		fetched:  false,
		pf:       rpc.NewNopPeerFeedback(),
		round:    round,
		prevRoot: prevRoot,
		thisRoot: thisRoot,
	}
	defer func() {
		select {
		case w.diffCh <- result:
		case <-ctx.Done():
		}
	}()

	// Check if the new root doesn't already exist.
	if w.localStorage.NodeDB().HasRoot(thisRoot) {
		return
	}

	result.fetched = true

	// Even if HasRoot returns false the root can still exist if it is equal
	// to the previous root and the root was emitted by the consensus committee
	// directly (e.g., during an epoch transition).
	if thisRoot.Hash.Equal(&prevRoot.Hash) {
		result.writeLog = storageApi.WriteLog{}
		return
	}

	// New root does not yet exist in storage and we need to fetch it from a peer.
	w.logger.Debug("calling GetDiff",
		"old_root", prevRoot,
		"new_root", thisRoot,
	)

	diffCtx, cancel := context.WithTimeout(ctx, diffResponseTimeout)
	defer cancel()

	wl, pf, err := w.getDiff(diffCtx, prevRoot, thisRoot)
	if err != nil {
		result.err = err
		return
	}
	result.pf = pf
	result.writeLog = wl
}

// getDiff fetches writelog using diff sync p2p protocol client.
//
// In case of no peers or error, it fallbacks to the legacy storage sync protocol.
func (w *Worker) getDiff(ctx context.Context, prevRoot, thisRoot storageApi.Root) (storageApi.WriteLog, rpc.PeerFeedback, error) {
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

func (w *Worker) finalize(ctx context.Context, summary *blockSummary) {
	err := w.localStorage.NodeDB().Finalize(summary.Roots)
	switch err {
	case nil:
		w.logger.Debug("storage round finalized",
			"round", summary.Round,
		)
	case storageApi.ErrAlreadyFinalized:
		// This can happen if we are restoring after a roothash migration or if
		// we crashed before updating the sync state.
		w.logger.Warn("storage round already finalized",
			"round", summary.Round,
		)
		err = nil
	default:
		w.logger.Error("failed to finalize storage round",
			"err", err,
			"round", summary.Round,
		)
	}

	result := finalizeResult{
		summary: summary,
		err:     err,
	}

	select {
	case w.finalizeCh <- result:
	case <-ctx.Done():
	}
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

func (w *Worker) flushSyncedState(summary *blockSummary) (uint64, error) {
	w.syncedLock.Lock()
	defer w.syncedLock.Unlock()

	w.syncedState = *summary
	if err := w.commonNode.Runtime.History().StorageSyncCheckpoint(w.syncedState.Round); err != nil {
		return 0, err
	}

	return w.syncedState.Round, nil
}

func (w *Worker) consensusCheckpointSyncer(ctx context.Context) {
	// Make sure we always create a checkpoint when the consensus layer creates a checkpoint. The
	// reason why we do this is to make it faster for storage nodes that use consensus state sync
	// to catch up as exactly the right checkpoint will be available.
	consensusCp := w.commonNode.Consensus.Checkpointer()
	if consensusCp == nil {
		return
	}

	// Wait for the common node to be initialized.
	select {
	case <-w.commonNode.Initialized():
	case <-ctx.Done():
		return
	}

	// Determine the maximum number of consensus checkpoints to keep.
	consensusParams, err := w.commonNode.Consensus.Core().GetParameters(ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("failed to fetch consensus parameters",
			"err", err,
		)
		return
	}

	ch, sub, err := consensusCp.WatchCheckpoints()
	if err != nil {
		w.logger.Error("failed to watch checkpoints",
			"err", err,
		)
		return
	}
	defer sub.Close()

	var (
		versions []uint64
		blkCh    <-chan *consensus.Block
		blkSub   pubsub.ClosableSubscription
	)
	defer func() {
		if blkCh != nil {
			blkSub.Close()
			blkSub = nil
			blkCh = nil
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case version := <-ch:
			// We need to wait for the next version as that is what will be in the consensus
			// checkpoint.
			versions = append(versions, version+1)
			// Make sure that we limit the size of the checkpoint queue.
			if uint64(len(versions)) > consensusParams.Parameters.StateCheckpointNumKept {
				versions = versions[1:]
			}

			w.logger.Debug("consensus checkpoint detected, queuing runtime checkpoint",
				"version", version+1,
				"num_versions", len(versions),
			)

			if blkCh == nil {
				blkCh, blkSub, err = w.commonNode.Consensus.Core().WatchBlocks(ctx)
				if err != nil {
					w.logger.Error("failed to watch blocks",
						"err", err,
					)
					continue
				}
			}
		case blk := <-blkCh:
			// If there's nothing remaining, unsubscribe.
			if len(versions) == 0 {
				w.logger.Debug("no more queued consensus checkpoint versions")

				blkSub.Close()
				blkSub = nil
				blkCh = nil
				continue
			}

			var newVersions []uint64
			for idx, version := range versions {
				if version > uint64(blk.Height) {
					// We need to wait for further versions.
					newVersions = versions[idx:]
					break
				}

				// Lookup what runtime round corresponds to the given consensus layer version and make
				// sure we checkpoint it.
				blk, err := w.commonNode.Consensus.RootHash().GetLatestBlock(ctx, &roothashApi.RuntimeRequest{
					RuntimeID: w.commonNode.Runtime.ID(),
					Height:    int64(version),
				})
				if err != nil {
					w.logger.Error("failed to get runtime block corresponding to consensus checkpoint",
						"err", err,
						"height", version,
					)
					continue
				}

				// We may have not yet synced the corresponding runtime round locally. In this case
				// we need to wait until this is the case.
				w.syncedLock.RLock()
				lastSyncedRound := w.syncedState.Round
				w.syncedLock.RUnlock()
				if blk.Header.Round > lastSyncedRound {
					w.logger.Debug("runtime round not available yet for checkpoint, waiting",
						"height", version,
						"round", blk.Header.Round,
						"last_synced_round", lastSyncedRound,
					)
					newVersions = versions[idx:]
					break
				}

				// Force runtime storage checkpointer to create a checkpoint at this round.
				w.logger.Info("consensus checkpoint, force runtime checkpoint",
					"height", version,
					"round", blk.Header.Round,
				)

				w.checkpointer.ForceCheckpoint(blk.Header.Round)
			}
			versions = newVersions
		}
	}
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

// Serve runs the state sync worker.
func (w *Worker) Serve(ctx context.Context) error { // nolint: gocyclo
	defer close(w.diffCh)

	// Wait for the common node to be initialized.
	select {
	case <-w.commonNode.Initialized():
	case <-ctx.Done():
		close(w.initCh)
		return ctx.Err()
	}

	w.logger.Info("starting")
	w.statusLock.Lock()
	w.status = api.StatusStarting
	w.statusLock.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-ctx.Done():
			w.statusLock.Lock()
			w.status = api.StatusStopping
			w.statusLock.Unlock()
		}
	}()
	defer w.logger.Info("stopped")

	go func() {
		err := w.checkpointer.Serve(ctx)
		w.logger.Error("checkpointer failed", "err", err)
	}()
	if config.GlobalConfig.Storage.Checkpointer.Enabled {
		go w.consensusCheckpointSyncer(ctx)
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
	lastFinalizedRound := w.syncedState.Round
	w.syncedLock.RUnlock()
	if lastFinalizedRound == defaultUndefinedRound || lastFinalizedRound < genesisBlock.Header.Round {
		lastFinalizedRound = w.undefinedRound
	}

	// Initialize genesis from the runtime descriptor.
	isInitialStartup := (lastFinalizedRound == w.undefinedRound)
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

	// Check if we are able to fetch the first block that we would be syncing if we used iterative
	// syncing. In case we cannot (likely because we synced the consensus layer via state sync), we
	// must wait for a later checkpoint to become available.
	if !w.checkpointSyncForced {
		w.statusLock.Lock()
		w.status = api.StatusSyncStartCheck
		w.statusLock.Unlock()

		// Determine what is the first round that we would need to sync.
		iterativeSyncStart := lastFinalizedRound
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
				lastFinalizedRound, err = w.flushSyncedState(summaryFromBlock(earlyBlk))
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
		"last_finalized_round", lastFinalizedRound,
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
			lastFinalizedRound, err = w.flushSyncedState(summary)
			if err != nil {
				return fmt.Errorf("failed to flush synced state %w", err)
			}
			w.logger.Info("checkpoint sync succeeded",
				logging.LogEvent, LogEventCheckpointSyncSuccess,
			)
		}
	}
	close(w.initCh)
	w.logger.Info("initialized")

	// Notify the checkpointer of the genesis round so it can be checkpointed.
	if w.checkpointer != nil {
		w.checkpointer.ForceCheckpoint(genesisBlock.Header.Round)
		w.checkpointer.Flush()
	}

	// Main syncing loop:
	err = nil
	var wg sync.WaitGroup

	latestBlockRound := w.undefinedRound // Don't register availability immediately, we want to know first how far behind consensus we are.
	lastFullyAppliedRound := lastFinalizedRound
	syncingRounds := make(map[uint64]*inFlight)
	summaryCache := make(map[uint64]*blockSummary)

	fetchPool := workerpool.New("storage_fetch/" + w.commonNode.Runtime.ID().String())
	fetchPool.Resize(config.GlobalConfig.Storage.FetcherCount)
	defer fetchPool.Stop()

	heartbeat := heartbeat{}
	heartbeat.reset()

	triggerRoundFetches := func() {
		for i := lastFullyAppliedRound + 1; i <= latestBlockRound; i++ {
			syncing, ok := syncingRounds[i]
			if ok && syncing.outstanding.hasAll() {
				continue
			}

			if !ok {
				if len(syncingRounds) >= maxInFlightRounds {
					break
				}

				syncing = &inFlight{
					startedAt:     time.Now(),
					awaitingRetry: outstandingMaskFull,
				}
				syncingRounds[i] = syncing

				if i == latestBlockRound {
					storageWorkerLastPendingRound.With(w.getMetricLabels()).Set(float64(i))
				}
			}
			w.logger.Debug("preparing round sync",
				"round", i,
				"outstanding_mask", syncing.outstanding,
				"awaiting_retry", syncing.awaitingRetry,
			)

			prev := summaryCache[i-1]
			this := summaryCache[i]
			prevRoots := make([]storageApi.Root, len(prev.Roots))
			copy(prevRoots, prev.Roots)
			for i := range prevRoots {
				if prevRoots[i].Type == storageApi.RootTypeIO {
					// IO roots aren't chained, so clear it (but leave cache intact).
					prevRoots[i] = storageApi.Root{
						Namespace: this.Namespace,
						Version:   this.Round,
						Type:      storageApi.RootTypeIO,
					}
					prevRoots[i].Hash.Empty()
					break
				}
			}

			for i := range prevRoots {
				rootType := prevRoots[i].Type
				if !syncing.outstanding.contains(rootType) && syncing.awaitingRetry.contains(rootType) {
					syncing.scheduleDiff(rootType)
					wg.Add(1)
					fetchPool.Submit(func() {
						defer wg.Done()
						w.fetchDiff(ctx, this.Round, prevRoots[i], this.Roots[i])
					})
				}
			}
		}
	}

	w.statusLock.Lock()
	w.status = api.StatusSyncingRounds
	w.statusLock.Unlock()

	pendingApply := &minRoundQueue{}
	pendingFinalize := &minRoundQueue{}

	// Main processing loop. When a new block arrives, its state and I/O roots are inspected.
	// If missing locally, diffs are fetched from peers, possibly for many rounds in parallel,
	// including all missing rounds since the last fully applied one. Fetched diffs are then applied
	// in round order, ensuring no gaps. Once a round has all its roots applied, background finalization
	// for that round is triggered asynchronously, not blocking concurrent fetching and diff application.
mainLoop:
	for {
		// Drain the Apply and Finalize queues first, before waiting for new events in the select below.

		// Apply fetched writelogs, but only if they are for the round after the last fully applied one
		// and current number of pending roots to be finalized is smaller than max allowed.
		applyNext := pendingApply.Len() > 0 &&
			lastFullyAppliedRound+1 == (*pendingApply)[0].GetRound() &&
			pendingFinalize.Len() < dbApi.MaxPendingVersions-1 // -1 since one may be already finalizing.
		if applyNext {
			lastDiff := heap.Pop(pendingApply).(*fetchedDiff)
			// Apply the write log if one exists.
			err = nil
			if lastDiff.fetched {
				err = w.localStorage.Apply(ctx, &storageApi.ApplyRequest{
					Namespace: lastDiff.thisRoot.Namespace,
					RootType:  lastDiff.thisRoot.Type,
					SrcRound:  lastDiff.prevRoot.Version,
					SrcRoot:   lastDiff.prevRoot.Hash,
					DstRound:  lastDiff.thisRoot.Version,
					DstRoot:   lastDiff.thisRoot.Hash,
					WriteLog:  lastDiff.writeLog,
				})
				switch {
				case err == nil:
					lastDiff.pf.RecordSuccess()
				case errors.Is(err, storageApi.ErrExpectedRootMismatch):
					lastDiff.pf.RecordBadPeer()
				default:
					w.logger.Error("can't apply write log",
						"err", err,
						"old_root", lastDiff.prevRoot,
						"new_root", lastDiff.thisRoot,
					)
					lastDiff.pf.RecordSuccess()
				}
			}

			syncing := syncingRounds[lastDiff.round]
			if err != nil {
				syncing.retry(lastDiff.thisRoot.Type)
				continue
			}
			syncing.outstanding.remove(lastDiff.thisRoot.Type)
			if !syncing.outstanding.isEmpty() || !syncing.awaitingRetry.isEmpty() {
				continue
			}

			// We have fully synced the given round.
			w.logger.Debug("finished syncing round", "round", lastDiff.round)
			delete(syncingRounds, lastDiff.round)
			summary := summaryCache[lastDiff.round]
			delete(summaryCache, lastDiff.round-1)
			lastFullyAppliedRound = lastDiff.round

			storageWorkerLastFullyAppliedRound.With(w.getMetricLabels()).Set(float64(lastDiff.round))
			storageWorkerRoundSyncLatency.With(w.getMetricLabels()).Observe(time.Since(syncing.startedAt).Seconds())

			// Finalize storage for this round. This happens asynchronously
			// with respect to Apply operations for subsequent rounds.
			heap.Push(pendingFinalize, summary)

			continue
		}

		// Check if any new rounds were fully applied and need to be finalized.
		// Only finalize if it's the round after the one that was finalized last.
		// As a consequence at most one finalization can be happening at the time.
		if len(*pendingFinalize) > 0 && lastFinalizedRound+1 == (*pendingFinalize)[0].GetRound() {
			lastSummary := heap.Pop(pendingFinalize).(*blockSummary)
			wg.Add(1)
			go func() { // Don't block fetching and applying remaining rounds.
				defer wg.Done()
				w.finalize(ctx, lastSummary)
			}()
			continue
		}

		select {
		case inBlk := <-w.blockCh.Out():
			blk := inBlk.(*block.Block)
			w.logger.Debug("incoming block",
				"round", blk.Header.Round,
				"last_fully_applied", lastFullyAppliedRound,
				"last_finalized", lastFinalizedRound,
			)

			// Check if we're far enough to reasonably register as available.
			latestBlockRound = blk.Header.Round
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)

			if _, ok := summaryCache[lastFullyAppliedRound]; !ok && lastFullyAppliedRound == w.undefinedRound {
				dummy := blockSummary{
					Namespace: blk.Header.Namespace,
					Round:     lastFullyAppliedRound + 1,
					Roots: []storageApi.Root{
						{
							Version: lastFullyAppliedRound + 1,
							Type:    storageApi.RootTypeIO,
						},
						{
							Version: lastFullyAppliedRound + 1,
							Type:    storageApi.RootTypeState,
						},
					},
				}
				dummy.Roots[0].Empty()
				dummy.Roots[1].Empty()
				summaryCache[lastFullyAppliedRound] = &dummy
			}
			// Determine if we need to fetch any old block summaries. In case the first
			// round is an undefined round, we need to start with the following round
			// since the undefined round may be unsigned -1 and in this case the loop
			// would not do any iterations.
			startSummaryRound := lastFullyAppliedRound
			if startSummaryRound == w.undefinedRound {
				startSummaryRound++
			}
			for i := startSummaryRound; i < blk.Header.Round; i++ {
				if _, ok := summaryCache[i]; ok {
					continue
				}
				var oldBlock *block.Block
				oldBlock, err = w.commonNode.Runtime.History().GetCommittedBlock(ctx, i)
				if err != nil {
					err = fmt.Errorf("failed to get block for round %d (current round: %d): %w", i, blk.Header.Round, err)
					break mainLoop
				}
				summaryCache[i] = summaryFromBlock(oldBlock)
			}
			if _, ok := summaryCache[blk.Header.Round]; !ok {
				summaryCache[blk.Header.Round] = summaryFromBlock(blk)
			}

			triggerRoundFetches()
			heartbeat.reset()

		case <-heartbeat.C:
			if latestBlockRound != w.undefinedRound {
				w.logger.Debug("heartbeat", "in_flight_rounds", len(syncingRounds))
				triggerRoundFetches()
			}

		case item := <-w.diffCh:
			if item.err != nil {
				w.logger.Error("error calling getdiff",
					"err", item.err,
					"round", item.round,
					"old_root", item.prevRoot,
					"new_root", item.thisRoot,
					"fetched", item.fetched,
				)
				syncingRounds[item.round].retry(item.thisRoot.Type)
				break
			}

			heap.Push(pendingApply, item)
			// Item was successfully processed, trigger more round fetches.
			// This ensures that new rounds are processed as fast as possible
			// when we're syncing and are far behind.
			triggerRoundFetches()

		case finalized := <-w.finalizeCh:
			// If finalization failed, things start falling apart.
			// There's no point redoing it, since it's probably not a transient
			// error, and lastFinalizedRound also can't be updated legitimately.
			if finalized.err != nil {
				w.logger.Error("failed to finalize", "err", err, "summary", finalized.summary)
				err = fmt.Errorf("failed to finalize (round: %d): %w", finalized.summary.Round, finalized.err)
				break mainLoop
			}

			// No further sync or out of order handling needed here, since
			// only one finalize at a time is triggered (for round lastFinalizedLastRound+1)
			lastFinalizedRound, err = w.flushSyncedState(finalized.summary)
			if err != nil {
				w.logger.Error("failed to flush synced state",
					"err", err,
				)
			}
			storageWorkerLastFinalizedRound.With(w.getMetricLabels()).Set(float64(finalized.summary.Round))

			// Check if we're far enough to reasonably register as available.
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)

			// Notify the checkpointer that there is a new finalized round.
			if config.GlobalConfig.Storage.Checkpointer.Enabled {
				w.checkpointer.NotifyNewVersion(finalized.summary.Round)
			}

		case <-ctx.Done():
			err = ctx.Err()
			break mainLoop
		}
	}

	cancel() // Ctx has to be canceled so that fetcher go routines can be emptied.
	wg.Wait()
	// blockCh will be garbage-collected without being closed. It can potentially still contain
	// some new blocks, but only as many as were already in-flight at the point when the main
	// context was canceled.
	return err
}
