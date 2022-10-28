package committee

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
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	commonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registryApi "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	mkvsDB "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
	storagePub "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/pub"
	storageSync "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/sync"
)

var (
	_ committee.NodeHooks = (*Node)(nil)

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

	// maxInFlightRounds is the maximum number of rounds that should be fetched before waiting
	// for them to be applied.
	maxInFlightRounds = 100
)

type roundItem interface {
	GetRound() uint64
}

// outOfOrderRoundQueue is a Round()-based min priority queue.
type outOfOrderRoundQueue []roundItem

// Sorting interface.
func (q outOfOrderRoundQueue) Len() int           { return len(q) }
func (q outOfOrderRoundQueue) Less(i, j int) bool { return q[i].GetRound() < q[j].GetRound() }
func (q outOfOrderRoundQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *outOfOrderRoundQueue) Push(x interface{}) {
	*q = append(*q, x.(roundItem))
}

// Pop removes and returns the last element in the heap's array.
func (q *outOfOrderRoundQueue) Pop() interface{} {
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

// Node watches blocks for storage changes.
type Node struct { // nolint: maligned
	commonNode *committee.Node

	roleProvider    registration.RoleProvider
	rpcRoleProvider registration.RoleProvider
	roleAvailable   bool

	logger *logging.Logger

	localStorage storageApi.LocalBackend

	storageSync storageSync.Client

	undefinedRound uint64

	fetchPool *workerpool.Pool

	workerCommonCfg workerCommon.Config

	checkpointer         checkpoint.Checkpointer
	checkpointSyncCfg    *CheckpointSyncConfig
	checkpointSyncForced bool

	syncedLock  sync.RWMutex
	syncedState blockSummary

	blockCh    *channels.InfiniteChannel
	diffCh     chan *fetchedDiff
	finalizeCh chan finalizeResult

	ctx       context.Context
	ctxCancel context.CancelFunc

	quitCh       chan struct{}
	workerQuitCh chan struct{}

	initCh chan struct{}
}

func NewNode(
	commonNode *committee.Node,
	fetchPool *workerpool.Pool,
	roleProvider registration.RoleProvider,
	rpcRoleProvider registration.RoleProvider,
	workerCommonCfg workerCommon.Config,
	localStorage storageApi.LocalBackend,
	checkpointerCfg *checkpoint.CheckpointerConfig,
	checkpointSyncCfg *CheckpointSyncConfig,
) (*Node, error) {
	initMetrics()

	n := &Node{
		commonNode: commonNode,

		roleProvider:    roleProvider,
		rpcRoleProvider: rpcRoleProvider,

		logger: logging.GetLogger("worker/storage/committee").With("runtime_id", commonNode.Runtime.ID()),

		workerCommonCfg: workerCommonCfg,

		localStorage: localStorage,

		fetchPool: fetchPool,

		checkpointSyncCfg: checkpointSyncCfg,

		blockCh:    channels.NewInfiniteChannel(),
		diffCh:     make(chan *fetchedDiff),
		finalizeCh: make(chan finalizeResult),

		quitCh:       make(chan struct{}),
		workerQuitCh: make(chan struct{}),
		initCh:       make(chan struct{}),
	}

	// Validate checkpoint sync configuration.
	if err := checkpointSyncCfg.Validate(); err != nil {
		return nil, fmt.Errorf("bad checkpoint sync configuration: %w", err)
	}

	// Initialize sync state.
	n.syncedState.Round = defaultUndefinedRound

	n.ctx, n.ctxCancel = context.WithCancel(context.Background())

	// Create a new checkpointer if enabled.
	if checkpointerCfg != nil {
		checkpointerCfg = &checkpoint.CheckpointerConfig{
			Name:            "runtime",
			Namespace:       commonNode.Runtime.ID(),
			CheckInterval:   checkpointerCfg.CheckInterval,
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

				return &checkpoint.CreationParameters{
					Interval:       rt.Storage.CheckpointInterval,
					NumKept:        rt.Storage.CheckpointNumKept,
					ChunkSize:      rt.Storage.CheckpointChunkSize,
					InitialVersion: blk.Header.Round,
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
		var err error
		n.checkpointer, err = checkpoint.NewCheckpointer(
			n.ctx,
			localStorage.NodeDB(),
			localStorage.Checkpointer(),
			*checkpointerCfg,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create checkpointer: %w", err)
		}
	}

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{
		logger: n.logger,
		node:   n,
	})

	// Register storage sync service.
	commonNode.P2P.RegisterProtocolServer(storageSync.NewServer(commonNode.Runtime.ID(), localStorage))
	n.storageSync = storageSync.NewClient(commonNode.P2P, commonNode.Runtime.ID())

	// Register storage pub service if configured.
	if rpcRoleProvider != nil {
		commonNode.P2P.RegisterProtocolServer(storagePub.NewServer(commonNode.Runtime.ID(), localStorage))
	}

	return n, nil
}

// Service interface.

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start causes the worker to start responding to tendermint new block events.
func (n *Node) Start() error {
	go n.watchQuit()
	go n.worker()
	if n.checkpointer != nil {
		go n.consensusCheckpointSyncer()
	}
	return nil
}

// Stop causes the worker to stop watching and shut down.
func (n *Node) Stop() {
	n.ctxCancel()
}

// Quit returns a channel that will be closed when the worker stops.
func (n *Node) Quit() <-chan struct{} {
	return n.quitCh
}

// Cleanup cleans up any leftover state after the worker is stopped.
func (n *Node) Cleanup() {
	// Nothing to do here?
}

// Initialized returns a channel that will be closed once the worker finished starting up.
func (n *Node) Initialized() <-chan struct{} {
	return n.initCh
}

// GetStatus returns the storage committee node status.
func (n *Node) GetStatus(ctx context.Context) (*api.Status, error) {
	n.syncedLock.RLock()
	defer n.syncedLock.RUnlock()

	return &api.Status{
		LastFinalizedRound: n.syncedState.Round,
	}, nil
}

func (n *Node) PauseCheckpointer(pause bool) error {
	if !commonFlags.DebugDontBlameOasis() {
		return api.ErrCantPauseCheckpointer
	}
	n.checkpointer.Pause(pause)
	return nil
}

// GetLocalStorage returns the local storage backend used by this storage node.
func (n *Node) GetLocalStorage() storageApi.LocalBackend {
	return n.localStorage
}

// NodeHooks implementation.

func (n *Node) HandlePeerTx(ctx context.Context, tx []byte) error {
	// Nothing to do here.
	return nil
}

// HandleEpochTransitionLocked is guarded by CrossNode.
func (n *Node) HandleEpochTransitionLocked(snapshot *committee.EpochSnapshot) {
	// Nothing to do here.
}

// HandleNewBlockEarlyLocked is guarded by CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(*block.Block) {
	// Nothing to do here.
}

// HandleNewBlockLocked is guarded by CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	// Notify the state syncer that there is a new block.
	n.blockCh.In() <- blk
}

// HandleNewEventLocked is guarded by CrossNode.
func (n *Node) HandleNewEventLocked(*roothashApi.Event) {
	// Nothing to do here.
}

// HandleRuntimeHostEventLocked is guarded by CrossNode.
func (n *Node) HandleRuntimeHostEventLocked(ev *host.Event) {
	// Nothing to do here.
}

// Watcher implementation.

// GetLastSynced returns the height, IORoot hash and StateRoot hash of the last block that was fully synced to.
func (n *Node) GetLastSynced() (uint64, storageApi.Root, storageApi.Root) {
	n.syncedLock.RLock()
	defer n.syncedLock.RUnlock()

	var io, state storageApi.Root
	for _, root := range n.syncedState.Roots {
		switch root.Type {
		case storageApi.RootTypeIO:
			io = root
		case storageApi.RootTypeState:
			state = root
		}
	}

	return n.syncedState.Round, io, state
}

func (n *Node) fetchDiff(round uint64, prevRoot, thisRoot storageApi.Root) {
	result := &fetchedDiff{
		fetched:  false,
		pf:       rpc.NewNopPeerFeedback(),
		round:    round,
		prevRoot: prevRoot,
		thisRoot: thisRoot,
	}
	defer func() {
		n.diffCh <- result
	}()
	// Check if the new root doesn't already exist.
	if !n.localStorage.NodeDB().HasRoot(thisRoot) {
		result.fetched = true
		if thisRoot.Hash.Equal(&prevRoot.Hash) {
			// Even if HasRoot returns false the root can still exist if it is equal
			// to the previous root and the root was emitted by the consensus committee
			// directly (e.g., during an epoch transition). In this case we need to
			// still apply the (empty) write log.
			result.writeLog = storageApi.WriteLog{}
		} else {
			// New root does not yet exist in storage and we need to fetch it from a
			// remote node.
			n.logger.Debug("calling GetDiff",
				"old_root", prevRoot,
				"new_root", thisRoot,
			)

			ctx, cancel := context.WithCancel(n.ctx)
			defer cancel()

			rsp, pf, err := n.storageSync.GetDiff(ctx, &storageSync.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
			if err != nil {
				result.err = err
				return
			}
			result.pf = pf
			result.writeLog = rsp.WriteLog
		}
	}
}

func (n *Node) finalize(summary *blockSummary) {
	err := n.localStorage.NodeDB().Finalize(n.ctx, summary.Roots)
	switch err {
	case nil:
		n.logger.Debug("storage round finalized",
			"round", summary.Round,
		)
	case storageApi.ErrAlreadyFinalized:
		// This can happen if we are restoring after a roothash migration or if
		// we crashed before updating the sync state.
		n.logger.Warn("storage round already finalized",
			"round", summary.Round,
		)
		err = nil
	default:
		n.logger.Error("failed to finalize storage round",
			"err", err,
			"round", summary.Round,
		)
	}

	n.finalizeCh <- finalizeResult{
		summary: summary,
		err:     err,
	}
}

func (n *Node) initGenesis(rt *registryApi.Runtime, genesisBlock *block.Block) error {
	n.logger.Info("initializing storage at genesis")

	// Check what the latest finalized version in the database is as we may be using a database
	// from a previous version or network.
	latestVersion, _ := n.localStorage.NodeDB().GetLatestVersion()

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

		if n.localStorage.NodeDB().HasRoot(maybeRoot) {
			n.logger.Debug("latest version earlier than genesis state root, filling in versions",
				"genesis_state_root", genesisBlock.Header.StateRoot,
				"genesis_round", genesisBlock.Header.Round,
				"latest_version", latestVersion,
			)
			for v := latestVersion; v < stateRoot.Version; v++ {
				err := n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
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

				err = n.localStorage.NodeDB().Finalize(n.ctx, []storageApi.Root{{
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
		compatible = n.localStorage.NodeDB().HasRoot(stateRoot)
	}

	// If we are incompatible and the local version is greater or the same as the genesis version,
	// we cannot do anything. If the local version is lower we assume the node will sync from a
	// different node.
	if !compatible && latestVersion >= stateRoot.Version {
		n.logger.Error("existing state is incompatible with runtime genesis state",
			"genesis_state_root", genesisBlock.Header.StateRoot,
			"genesis_round", genesisBlock.Header.Round,
			"latest_version", latestVersion,
		)
		return fmt.Errorf("existing state is incompatible with runtime genesis state")
	}

	if !compatible {
		// Database is empty, so assume the state will be replicated from another node.
		n.logger.Warn("non-empty state root but no state available, assuming replication",
			"state_root", genesisBlock.Header.StateRoot,
		)
		n.checkpointSyncForced = true
	}
	return nil
}

func (n *Node) flushSyncedState(summary *blockSummary) (uint64, error) {
	n.syncedLock.Lock()
	defer n.syncedLock.Unlock()

	n.syncedState = *summary
	if err := n.commonNode.Runtime.History().StorageSyncCheckpoint(n.ctx, n.syncedState.Round); err != nil {
		return 0, err
	}

	return n.syncedState.Round, nil
}

func (n *Node) watchQuit() {
	// Close quit channel on any worker quitting.
	<-n.workerQuitCh
	close(n.quitCh)
}

func (n *Node) consensusCheckpointSyncer() {
	// Make sure we always create a checkpoint when the consensus layer creates a checkpoint. The
	// reason why we do this is to make it faster for storage nodes that use consensus state sync
	// to catch up as exactly the right checkpoint will be available.
	consensusCp := n.commonNode.Consensus.Checkpointer()
	if consensusCp == nil {
		return
	}

	// Wait for the common node to be initialized.
	select {
	case <-n.commonNode.Initialized():
	case <-n.ctx.Done():
		return
	}

	// Determine the maximum number of consensus checkpoints to keep.
	consensusParams, err := n.commonNode.Consensus.GetParameters(n.ctx, consensus.HeightLatest)
	if err != nil {
		n.logger.Error("failed to fetch consensus parameters",
			"err", err,
		)
		return
	}

	ch, sub, err := consensusCp.WatchCheckpoints()
	if err != nil {
		n.logger.Error("failed to watch checkpoints",
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
		case <-n.quitCh:
			return
		case <-n.ctx.Done():
			return
		case version := <-ch:
			// We need to wait for the next version as that is what will be in the consensus
			// checkpoint.
			versions = append(versions, version+1)
			// Make sure that we limit the size of the checkpoint queue.
			if uint64(len(versions)) > consensusParams.Parameters.StateCheckpointNumKept {
				versions = versions[1:]
			}

			n.logger.Debug("consensus checkpoint detected, queuing runtime checkpoint",
				"version", version+1,
				"num_versions", len(versions),
			)

			if blkCh == nil {
				blkCh, blkSub, err = n.commonNode.Consensus.WatchBlocks(n.ctx)
				if err != nil {
					n.logger.Error("failed to watch blocks",
						"err", err,
					)
					continue
				}
			}
		case blk := <-blkCh:
			// If there's nothing remaining, unsubscribe.
			if len(versions) == 0 {
				n.logger.Debug("no more queued consensus checkpoint versions")

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
				blk, err := n.commonNode.Consensus.RootHash().GetLatestBlock(n.ctx, &roothashApi.RuntimeRequest{
					RuntimeID: n.commonNode.Runtime.ID(),
					Height:    int64(version),
				})
				if err != nil {
					n.logger.Error("failed to get runtime block corresponding to consensus checkpoint",
						"err", err,
						"height", version,
					)
					continue
				}

				// We may have not yet synced the corresponding runtime round locally. In this case
				// we need to wait until this is the case.
				n.syncedLock.RLock()
				lastSyncedRound := n.syncedState.Round
				n.syncedLock.RUnlock()
				if blk.Header.Round > lastSyncedRound {
					n.logger.Debug("runtime round not available yet for checkpoint, waiting",
						"height", version,
						"round", blk.Header.Round,
						"last_synced_round", lastSyncedRound,
					)
					newVersions = versions[idx:]
					break
				}

				// Force runtime storage checkpointer to create a checkpoint at this round.
				n.logger.Info("consensus checkpoint, force runtime checkpoint",
					"height", version,
					"round", blk.Header.Round,
				)

				n.checkpointer.ForceCheckpoint(blk.Header.Round)
			}
			versions = newVersions
		}
	}
}

// This is only called from the main worker goroutine, so no locking should be necessary.
func (n *Node) nudgeAvailability(lastSynced, latest uint64) {
	if lastSynced == n.undefinedRound || latest == n.undefinedRound {
		return
	}
	if latest-lastSynced < maximumRoundDelayForAvailability && !n.roleAvailable {
		n.roleProvider.SetAvailable(func(nd *node.Node) error {
			return nil
		})
		if n.rpcRoleProvider != nil {
			n.rpcRoleProvider.SetAvailable(func(nd *node.Node) error {
				return nil
			})
		}
		n.roleAvailable = true
	}
	if latest-lastSynced > minimumRoundDelayForUnavailability && n.roleAvailable {
		n.roleProvider.SetUnavailable()
		if n.rpcRoleProvider != nil {
			n.rpcRoleProvider.SetUnavailable()
		}
		n.roleAvailable = false
	}
}

func (n *Node) worker() { // nolint: gocyclo
	defer close(n.workerQuitCh)
	defer close(n.diffCh)

	// Wait for the common node to be initialized.
	select {
	case <-n.commonNode.Initialized():
	case <-n.ctx.Done():
		close(n.initCh)
		return
	}

	n.logger.Info("starting committee node")

	// Determine genesis block.
	genesisBlock, err := n.commonNode.Consensus.RootHash().GetGenesisBlock(n.ctx, &roothashApi.RuntimeRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		n.logger.Error("can't retrieve genesis block", "err", err)
		return
	}
	n.undefinedRound = genesisBlock.Header.Round - 1

	// Determine last finalized storage version.
	if version, dbNonEmpty := n.localStorage.NodeDB().GetLatestVersion(); dbNonEmpty {
		var blk *block.Block
		blk, err = n.commonNode.Runtime.History().GetCommittedBlock(n.ctx, version)
		switch err {
		case nil:
			// Set last synced version to last finalized storage version.
			if _, err = n.flushSyncedState(summaryFromBlock(blk)); err != nil {
				n.logger.Error("failed to flush synced state", "err", err)
				return
			}
		default:
			// Failed to fetch historic block. This is fine when the network just went through a
			// dump/restore upgrade and we don't have any information before genesis. We treat the
			// database as unsynced and will proceed to either use checkpoints or sync iteratively.
			n.logger.Warn("failed to fetch historic block",
				"err", err,
				"round", version,
			)
		}
	}

	var fetcherGroup sync.WaitGroup

	n.syncedLock.RLock()
	cachedLastRound := n.syncedState.Round
	n.syncedLock.RUnlock()
	if cachedLastRound == defaultUndefinedRound || cachedLastRound < genesisBlock.Header.Round {
		cachedLastRound = n.undefinedRound
	}

	// Initialize genesis from the runtime descriptor.
	isInitialStartup := (cachedLastRound == n.undefinedRound)
	if isInitialStartup {
		var rt *registryApi.Runtime
		rt, err = n.commonNode.Runtime.ActiveDescriptor(n.ctx)
		if err != nil {
			n.logger.Error("failed to retrieve runtime registry descriptor",
				"err", err,
			)
			return
		}
		if err = n.initGenesis(rt, genesisBlock); err != nil {
			n.logger.Error("failed to initialize storage at genesis",
				"err", err,
			)
			return
		}
	}

	// Notify the checkpointer of the genesis round so it can be checkpointed.
	if n.checkpointer != nil {
		n.checkpointer.ForceCheckpoint(genesisBlock.Header.Round)
		n.checkpointer.Flush()
	}

	// Check if we are able to fetch the first block that we would be syncing if we used iterative
	// syncing. In case we cannot (likely because we synced the consensus layer via state sync), we
	// must wait for a later checkpoint to become available.
	if !n.checkpointSyncForced {
		// Determine what is the first round that we would need to sync.
		iterativeSyncStart := cachedLastRound
		if iterativeSyncStart == n.undefinedRound {
			iterativeSyncStart++
		}

		// Check if we actually have information about that round. This assumes that any reindexing
		// was already performed (the common node would not indicate being initialized otherwise).
		_, err = n.commonNode.Runtime.History().GetCommittedBlock(n.ctx, iterativeSyncStart)
	SyncStartCheck:
		switch {
		case err == nil:
		case errors.Is(err, roothashApi.ErrNotFound):
			// No information is available about the initial round. Query the earliest historic
			// block and check if that block has the genesis state root and empty I/O root.
			var earlyBlk *block.Block
			earlyBlk, err = n.commonNode.Runtime.History().GetEarliestBlock(n.ctx)
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
				n.logger.Debug("filling in versions to genesis",
					"genesis_round", genesisBlock.Header.Round,
					"earliest_round", earlyBlk.Header.Round,
				)
				for v := genesisBlock.Header.Round; v < earlyBlk.Header.Round; v++ {
					err = n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
						Namespace: n.commonNode.Runtime.ID(),
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
						n.logger.Error("failed to fill in version",
							"version", v,
							"err", err,
						)
						return
					}

					err = n.localStorage.NodeDB().Finalize(n.ctx, []storageApi.Root{{
						Namespace: n.commonNode.Runtime.ID(),
						Version:   v + 1,
						Type:      storageApi.RootTypeState,
						Hash:      genesisBlock.Header.StateRoot,
						// We can ignore I/O roots.
					}})
					if err != nil {
						n.logger.Error("failed to finalize filled in version",
							"version", v,
							"err", err,
						)
						return
					}
				}
				cachedLastRound, err = n.flushSyncedState(summaryFromBlock(earlyBlk))
				if err != nil {
					n.logger.Error("failed to flush synced state",
						"err", err,
					)
					return
				}
				// No need to force a checkpoint sync.
				break SyncStartCheck
			default:
				// This should never happen as the block should exist.
				n.logger.Warn("failed to query earliest block in local history",
					"err", err,
				)
			}

			// No information is available about this round, force checkpoint sync.
			n.logger.Warn("forcing checkpoint sync as we don't have authoritative block info",
				"round", iterativeSyncStart,
			)
			n.checkpointSyncForced = true
		default:
			// Unknown error while fetching block information, abort.
			n.logger.Error("failed to query block",
				"err", err,
			)
			return
		}
	}

	n.logger.Info("worker initialized",
		"genesis_round", genesisBlock.Header.Round,
		"last_synced", cachedLastRound,
	)

	outOfOrderDoneDiffs := &outOfOrderRoundQueue{}
	outOfOrderFinalizable := &outOfOrderRoundQueue{}
	syncingRounds := make(map[uint64]*inFlight)
	hashCache := make(map[uint64]*blockSummary)
	lastFullyAppliedRound := cachedLastRound

	heap.Init(outOfOrderDoneDiffs)

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
	if (isInitialStartup && !n.checkpointSyncCfg.Disabled) || n.checkpointSyncForced {
		var (
			summary *blockSummary
			attempt int
		)
	CheckpointSyncRetry:
		for {
			summary, err = n.syncCheckpoints(genesisBlock.Header.Round, n.checkpointSyncCfg.Disabled)
			if err == nil {
				break
			}

			attempt++
			switch n.checkpointSyncForced {
			case true:
				// We have no other options but to perform a checkpoint sync as we are missing
				// either state or authoritative blocks.
				n.logger.Info("checkpoint sync required, retrying",
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
				n.logger.Info("first checkpoint sync failed, trying once more", "err", err)
			}

			// Delay before retrying.
			select {
			case <-time.After(checkpointSyncRetryDelay):
			case <-n.ctx.Done():
				return
			}
		}
		if err != nil {
			n.logger.Info("checkpoint sync failed", "err", err)
		} else {
			cachedLastRound, err = n.flushSyncedState(summary)
			if err != nil {
				n.logger.Error("failed to flush synced state",
					"err", err,
				)
				return
			}
			lastFullyAppliedRound = cachedLastRound
			n.logger.Info("checkpoint sync succeeded",
				logging.LogEvent, LogEventCheckpointSyncSuccess,
			)
		}
	}
	close(n.initCh)

	// Don't register availability immediately, we want to know first how far behind consensus we are.
	latestBlockRound := n.undefinedRound

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
					storageWorkerLastPendingRound.With(n.getMetricLabels()).Set(float64(i))
				}
			}
			n.logger.Debug("preparing round sync",
				"round", i,
				"outstanding_mask", syncing.outstanding,
				"awaiting_retry", syncing.awaitingRetry,
			)

			prev := hashCache[i-1] // Closures take refs, so they need new variables here.
			this := hashCache[i]
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
					fetcherGroup.Add(1)
					n.fetchPool.Submit(func(round uint64, prevRoot, thisRoot storageApi.Root) func() {
						return func() {
							defer fetcherGroup.Done()
							n.fetchDiff(round, prevRoot, thisRoot)
						}
					}(this.Round, prevRoots[i], this.Roots[i]))
				}
			}
		}
	}

	// Main processing loop. When a new block comes in, its state and io roots are inspected and their
	// writelogs fetched from remote storage nodes in case we don't have them locally yet. Fetches are
	// asynchronous and, once complete, trigger local Apply operations. These are serialized
	// per round (all applies for a given round have to be complete before applying anyting for following
	// rounds) using the outOfOrderDoneDiffs priority queue and outOfOrderFinalizable. Once a round has all its write
	// logs applied, a Finalize for it is triggered, again serialized by round but otherwise asynchronous
	// (outOfOrderFinalizable and cachedLastRound).
mainLoop:
	for {
		// Drain the Apply and Finalize queues first, before waiting for new events in the select
		// below. Applies are drained first, followed by finalizations (which are asynchronous
		// but serialized, i.e. only one Finalize can be in progress at a time).

		// Apply any writelogs that came in through fetchDiff, but only if they are for the round
		// after the last fully applied one (lastFullyAppliedRound).
		if len(*outOfOrderDoneDiffs) > 0 && lastFullyAppliedRound+1 == (*outOfOrderDoneDiffs)[0].GetRound() {
			lastDiff := heap.Pop(outOfOrderDoneDiffs).(*fetchedDiff)
			// Apply the write log if one exists.
			err = nil
			if lastDiff.fetched {
				err = n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
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
					n.logger.Error("can't apply write log",
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
			} else {
				// Check if we have fully synced the given round. If we have, we can proceed
				// with the Finalize operation.
				syncing.outstanding.remove(lastDiff.thisRoot.Type)
				if syncing.outstanding.isEmpty() && syncing.awaitingRetry.isEmpty() {
					n.logger.Debug("finished syncing round", "round", lastDiff.round)
					delete(syncingRounds, lastDiff.round)
					summary := hashCache[lastDiff.round]
					delete(hashCache, lastDiff.round-1)

					storageWorkerLastSyncedRound.With(n.getMetricLabels()).Set(float64(lastDiff.round))
					storageWorkerRoundSyncLatency.With(n.getMetricLabels()).Observe(time.Since(syncing.startedAt).Seconds())

					// Finalize storage for this round. This happens asynchronously
					// with respect to Apply operations for subsequent rounds.
					lastFullyAppliedRound = lastDiff.round
					heap.Push(outOfOrderFinalizable, summary)
				}
			}

			continue
		}

		// Check if any new rounds were fully applied and need to be finalized. Only finalize
		// if it's the round after the one that was finalized last (cachedLastRound).
		// The finalization happens asynchronously with respect to this worker loop and any
		// applies that happen for subsequent rounds (which can proceed while earlier rounds are
		// still finalizing).
		if len(*outOfOrderFinalizable) > 0 && cachedLastRound+1 == (*outOfOrderFinalizable)[0].GetRound() {
			lastSummary := heap.Pop(outOfOrderFinalizable).(*blockSummary)
			fetcherGroup.Add(1)
			go func(lastSummary *blockSummary) {
				defer fetcherGroup.Done()
				n.finalize(lastSummary)
			}(lastSummary)
			continue
		}

		select {
		case inBlk := <-n.blockCh.Out():
			blk := inBlk.(*block.Block)
			n.logger.Debug("incoming block",
				"round", blk.Header.Round,
				"last_synced", lastFullyAppliedRound,
				"last_finalized", cachedLastRound,
			)

			// Check if we're far enough to reasonably register as available.
			latestBlockRound = blk.Header.Round
			n.nudgeAvailability(cachedLastRound, latestBlockRound)

			if _, ok := hashCache[lastFullyAppliedRound]; !ok && lastFullyAppliedRound == n.undefinedRound {
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
				hashCache[lastFullyAppliedRound] = &dummy
			}
			// Determine if we need to fetch any old block summaries. In case the first
			// round is an undefined round, we need to start with the following round
			// since the undefined round may be unsigned -1 and in this case the loop
			// would not do any iterations.
			startSummaryRound := lastFullyAppliedRound
			if startSummaryRound == n.undefinedRound {
				startSummaryRound++
			}
			for i := startSummaryRound; i < blk.Header.Round; i++ {
				if _, ok := hashCache[i]; ok {
					continue
				}
				var oldBlock *block.Block
				oldBlock, err = n.commonNode.Runtime.History().GetCommittedBlock(n.ctx, i)
				if err != nil {
					n.logger.Error("can't get block for round",
						"err", err,
						"round", i,
						"current_round", blk.Header.Round,
					)
					panic("can't get block in storage worker")
				}
				hashCache[i] = summaryFromBlock(oldBlock)
			}
			if _, ok := hashCache[blk.Header.Round]; !ok {
				hashCache[blk.Header.Round] = summaryFromBlock(blk)
			}

			triggerRoundFetches()
			heartbeat.reset()

		case <-heartbeat.C:
			if latestBlockRound != n.undefinedRound {
				n.logger.Debug("heartbeat", "in_flight_rounds", len(syncingRounds))
				triggerRoundFetches()
			}

		case item := <-n.diffCh:
			if item.err != nil {
				n.logger.Error("error calling getdiff",
					"err", item.err,
					"round", item.round,
					"old_root", item.prevRoot,
					"new_root", item.thisRoot,
					"fetched", item.fetched,
				)
				syncingRounds[item.round].retry(item.thisRoot.Type)
			} else {
				heap.Push(outOfOrderDoneDiffs, item)
			}

			triggerRoundFetches()

		case finalized := <-n.finalizeCh:
			// If finalization failed, things start falling apart.
			// There's no point redoing it, since it's probably not a transient
			// error, and cachedLastRound also can't be updated legitimately.
			if finalized.err == nil {
				// No further sync or out of order handling needed here, since
				// only one finalize at a time is triggered (for round cachedLastRound+1)
				cachedLastRound, err = n.flushSyncedState(finalized.summary)
				if err != nil {
					n.logger.Error("failed to flush synced state",
						"err", err,
					)
				}
				storageWorkerLastFullRound.With(n.getMetricLabels()).Set(float64(finalized.summary.Round))

				// Check if we're far enough to reasonably register as available.
				n.nudgeAvailability(cachedLastRound, latestBlockRound)

				// Notify the checkpointer that there is a new finalized round.
				if n.checkpointer != nil {
					n.checkpointer.NotifyNewVersion(finalized.summary.Round)
				}
			} else {
				// This is a cant-happen situation and there's no useful way
				// to recover from it. Just request a node shutdown and stop fussing
				// since, from this point onwards, syncing is effectively blocked.
				_, _ = n.commonNode.HostNode.RequestShutdown()
			}

		case <-n.ctx.Done():
			break mainLoop
		}
	}

	fetcherGroup.Wait()
	// blockCh will be garbage-collected without being closed. It can potentially still contain
	// some new blocks, but only as many as were already in-flight at the point when the main
	// context was canceled.
}

type pruneHandler struct {
	logger *logging.Logger
	node   *Node
}

func (p *pruneHandler) Prune(ctx context.Context, rounds []uint64) error {
	// Make sure we never prune past what was synced.
	lastSycnedRound, _, _ := p.node.GetLastSynced()

	for _, round := range rounds {
		if round >= lastSycnedRound {
			return fmt.Errorf("worker/storage: tried to prune past last synced round (last synced: %d)",
				lastSycnedRound,
			)
		}

		// TODO: Make sure we don't prune rounds that need to be checkpointed but haven't been yet.

		p.logger.Debug("pruning storage for round", "round", round)

		// Prune given block.
		err := p.node.localStorage.NodeDB().Prune(ctx, round)
		switch err {
		case nil:
		case mkvsDB.ErrNotEarliest:
			p.logger.Debug("skipping non-earliest round",
				"round", round,
			)
			continue
		default:
			p.logger.Error("failed to prune block",
				"err", err,
			)
			return err
		}
	}

	return nil
}
