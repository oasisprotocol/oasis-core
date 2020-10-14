package committee

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryApi "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashApi "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes/grpc"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/client"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	mkvsDB "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

var (
	_ committee.NodeHooks = (*Node)(nil)

	// ErrNonLocalBackend is the error returned when the storage backend doesn't implement the LocalBackend interface.
	ErrNonLocalBackend = errors.New("storage: storage backend doesn't support local storage")

	storageWorkerLastFullRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_full_round",
			Help: "The last round that was fully synced and finalized.",
		},
		[]string{"runtime"},
	)

	storageWorkerLastSyncedRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_synced_round",
			Help: "The last round that was synced but not yet finalized.",
		},
		[]string{"runtime"},
	)

	storageWorkerLastPendingRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_pending_round",
			Help: "The last round that is in-flight for syncing.",
		},
		[]string{"runtime"},
	)

	storageWorkerCollectors = []prometheus.Collector{
		storageWorkerLastFullRound,
		storageWorkerLastSyncedRound,
		storageWorkerLastPendingRound,
	}

	prometheusOnce sync.Once
)

const (
	// RoundLatest is a magic value for the latest round.
	RoundLatest = math.MaxUint64

	defaultUndefinedRound = ^uint64(0)

	checkpointSyncRetryDelay = 10 * time.Second
)

// outstandingMask records which storage roots still need to be synced or need to be retried.
type outstandingMask uint

const (
	maskNone  = outstandingMask(0x0)
	maskIO    = outstandingMask(0x1)
	maskState = outstandingMask(0x2)
	maskAll   = maskIO | maskState
)

func (o outstandingMask) String() string {
	var represented []string
	if o&maskIO != 0 {
		represented = append(represented, "io")
	}
	if o&maskState != 0 {
		represented = append(represented, "state")
	}
	return fmt.Sprintf("outstanding_mask{%s}", strings.Join(represented, ", "))
}

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
	fetchMask outstandingMask
	fetched   bool
	err       error
	round     uint64
	prevRoot  mkvsNode.Root
	thisRoot  mkvsNode.Root
	writeLog  storageApi.WriteLog
}

func (d *fetchedDiff) GetRound() uint64 {
	return d.round
}

// blockSummary is a short summary of a single block.Block.
type blockSummary struct {
	Namespace common.Namespace `json:"namespace"`
	Round     uint64           `json:"round"`
	IORoot    mkvsNode.Root    `json:"io_root"`
	StateRoot mkvsNode.Root    `json:"state_root"`
}

func (s *blockSummary) GetRound() uint64 {
	return s.Round
}

func summaryFromBlock(blk *block.Block) *blockSummary {
	return &blockSummary{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		IORoot: mkvsNode.Root{
			Namespace: blk.Header.Namespace,
			Version:   blk.Header.Round,
			Type:      mkvsNode.RootTypeIO,
			Hash:      blk.Header.IORoot,
		},
		StateRoot: mkvsNode.Root{
			Namespace: blk.Header.Namespace,
			Version:   blk.Header.Round,
			Type:      mkvsNode.RootTypeState,
			Hash:      blk.Header.StateRoot,
		},
	}
}

// watcherState is the (persistent) watcher state.
type watcherState struct {
	LastBlock blockSummary `json:"last_block"`
}

// Node watches blocks for storage changes.
type Node struct {
	commonNode *committee.Node

	roleProvider registration.RoleProvider

	logger *logging.Logger

	localStorage storageApi.LocalBackend

	storageNodes     nodes.NodeDescriptorLookup
	storageNodesGrpc grpc.NodesClient
	storageClient    storageApi.ClientBackend

	grpcPolicy     *policy.DynamicRuntimePolicyChecker
	undefinedRound uint64

	fetchPool *workerpool.Pool

	stateStore *persistent.ServiceStore

	workerCommonCfg workerCommon.Config

	checkpointer           checkpoint.Checkpointer
	checkpointSyncDisabled bool
	checkpointSyncForced   bool

	syncedLock  sync.RWMutex
	syncedState watcherState

	blockCh    *channels.InfiniteChannel
	diffCh     chan *fetchedDiff
	finalizeCh chan *blockSummary

	ctx       context.Context
	ctxCancel context.CancelFunc

	quitCh          chan struct{}
	rtWatcherQuitCh chan struct{}
	workerQuitCh    chan struct{}

	initCh chan struct{}
}

func NewNode(
	commonNode *committee.Node,
	grpcPolicy *policy.DynamicRuntimePolicyChecker,
	fetchPool *workerpool.Pool,
	store *persistent.ServiceStore,
	roleProvider registration.RoleProvider,
	workerCommonCfg workerCommon.Config,
	localStorage storageApi.LocalBackend,
	checkpointerCfg *checkpoint.CheckpointerConfig,
	checkpointSyncDisabled bool,
) (*Node, error) {
	n := &Node{
		commonNode: commonNode,

		roleProvider: roleProvider,

		logger: logging.GetLogger("worker/storage/committee").With("runtime_id", commonNode.Runtime.ID()),

		workerCommonCfg: workerCommonCfg,

		localStorage: localStorage,
		grpcPolicy:   grpcPolicy,

		fetchPool: fetchPool,

		stateStore: store,

		checkpointSyncDisabled: checkpointSyncDisabled,

		blockCh:    channels.NewInfiniteChannel(),
		diffCh:     make(chan *fetchedDiff),
		finalizeCh: make(chan *blockSummary),

		quitCh:          make(chan struct{}),
		rtWatcherQuitCh: make(chan struct{}),
		workerQuitCh:    make(chan struct{}),
		initCh:          make(chan struct{}),
	}

	n.syncedState.LastBlock.Round = defaultUndefinedRound
	rtID := commonNode.Runtime.ID()
	err := store.GetCBOR(rtID[:], &n.syncedState)
	if err != nil && err != persistent.ErrNotFound {
		return nil, fmt.Errorf("storage worker: failed to restore sync state: %w", err)
	}

	n.ctx, n.ctxCancel = context.WithCancel(context.Background())

	// Create a new storage client that will be used for remote sync.
	// This storage client connects to all registered storage nodes for the runtime.
	nl, err := nodes.NewRuntimeNodeLookup(
		n.ctx,
		n.commonNode.Consensus.Registry(),
		rtID,
	)
	if err != nil {
		return nil, fmt.Errorf("group: failed to create runtime node watcher: %w", err)
	}

	n.storageNodes = nodes.NewFilteredNodeLookup(nl,
		nodes.WithAllFilters(
			// Ignore self.
			nodes.IgnoreNodeFilter(n.commonNode.Identity.NodeSigner.Public()),
			// Only storage nodes.
			nodes.TagFilter(nodes.TagsForRoleMask(node.RoleStorageWorker)[0]),
		),
	)
	storageNodesGrpc, err := grpc.NewNodesClient(
		n.ctx,
		n.storageNodes,
		grpc.WithClientAuthentication(n.commonNode.Identity),
	)
	if err != nil {
		return nil, fmt.Errorf("storage/client: failed to create nodes gRPC client: %w", err)
	}
	n.storageNodesGrpc = storageNodesGrpc

	scl, err := client.NewForNodesClient(
		n.ctx,
		n.storageNodesGrpc,
		n.commonNode.Runtime,
	)
	if err != nil {
		return nil, fmt.Errorf("storage worker: failed to create client: %w", err)
	}
	n.storageClient = scl.(storageApi.ClientBackend)

	// Create a new checkpointer if enabled.
	if checkpointerCfg != nil {
		checkpointerCfg = &checkpoint.CheckpointerConfig{
			Name:            "runtime",
			Namespace:       commonNode.Runtime.ID(),
			CheckInterval:   checkpointerCfg.CheckInterval,
			RootsPerVersion: 2, // State root and I/O root.
			GetParameters: func(ctx context.Context) (*checkpoint.CreationParameters, error) {
				rt, rerr := commonNode.Runtime.RegistryDescriptor(ctx)
				if rerr != nil {
					return nil, fmt.Errorf("failed to retrieve runtime descriptor: %w", rerr)
				}

				blk, rerr := commonNode.Consensus.RootHash().GetGenesisBlock(ctx, rt.ID, consensus.HeightLatest)
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
				blk, berr := commonNode.Runtime.History().GetBlock(ctx, version)
				if berr != nil {
					return nil, berr
				}

				return blk.Header.StorageRoots(), nil
			},
		}
		n.checkpointer, err = checkpoint.NewCheckpointer(
			n.ctx,
			localStorage.NodeDB(),
			localStorage.Checkpointer(),
			*checkpointerCfg,
		)
		if err != nil {
			return nil, fmt.Errorf("storage worker: failed to create checkpointer: %w", err)
		}
	}

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{
		logger: n.logger,
		node:   n,
	})

	prometheusOnce.Do(func() {
		prometheus.MustRegister(storageWorkerCollectors...)
	})

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
		LastFinalizedRound: n.syncedState.LastBlock.Round,
	}, nil
}

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.commonNode.Runtime.ID().String(),
	}
}

// NodeHooks implementation.

func (n *Node) HandlePeerMessage(context.Context, *p2p.Message, bool) (bool, error) {
	// Nothing to do here.
	return false, nil
}

// Guarded by CrossNode.
func (n *Node) HandleEpochTransitionLocked(snapshot *committee.EpochSnapshot) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(*block.Block) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	// Notify the state syncer that there is a new block.
	n.blockCh.In() <- blk
}

// Guarded by CrossNode.
func (n *Node) HandleNewEventLocked(*roothashApi.Event) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (n *Node) HandleNodeUpdateLocked(update *nodes.NodeUpdate, snapshot *committee.EpochSnapshot) {
	// Nothing to do here.
	// Storage worker uses a separate watcher.
}

// Watcher implementation.

// GetLastSynced returns the height, IORoot hash and StateRoot hash of the last block that was fully synced to.
func (n *Node) GetLastSynced() (uint64, mkvsNode.Root, mkvsNode.Root) {
	n.syncedLock.RLock()
	defer n.syncedLock.RUnlock()

	return n.syncedState.LastBlock.Round, n.syncedState.LastBlock.IORoot, n.syncedState.LastBlock.StateRoot
}

// ForceFinalize forces a storage finalization for the given round.
func (n *Node) ForceFinalize(ctx context.Context, round uint64) error {
	n.logger.Debug("forcing round finalization",
		"round", round,
	)

	var block *block.Block
	var err error

	if round == RoundLatest {
		block, err = n.commonNode.Consensus.RootHash().GetLatestBlock(ctx, n.commonNode.Runtime.ID(), consensus.HeightLatest)
	} else {
		block, err = n.commonNode.Runtime.History().GetBlock(ctx, round)
	}

	if err != nil {
		return err
	}
	return n.localStorage.NodeDB().Finalize(ctx, block.Header.StorageRoots())
}

func (n *Node) fetchDiff(round uint64, prevRoot, thisRoot *mkvsNode.Root, fetchMask outstandingMask) {
	result := &fetchedDiff{
		fetchMask: fetchMask,
		fetched:   false,
		round:     round,
		prevRoot:  *prevRoot,
		thisRoot:  *thisRoot,
	}
	defer func() {
		n.diffCh <- result
	}()
	// Check if the new root doesn't already exist.
	if !n.localStorage.NodeDB().HasRoot(*thisRoot) {
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
				"fetch_mask", fetchMask,
			)

			// Prioritize committee nodes.
			ctx := n.ctx
			if committee := n.commonNode.Group.GetEpochSnapshot().GetStorageCommittee(); committee != nil {
				ctx = storageApi.WithNodePriorityHintFromMap(ctx, committee.PublicKeys)
			}
			it, err := n.storageClient.GetDiff(ctx, &storageApi.GetDiffRequest{StartRoot: *prevRoot, EndRoot: *thisRoot})
			if err != nil {
				result.err = err
				return
			}
			for {
				more, err := it.Next()
				if err != nil {
					result.err = err
					return
				}
				if !more {
					break
				}

				chunk, err := it.Value()
				if err != nil {
					result.err = err
					return
				}
				result.writeLog = append(result.writeLog, chunk)
			}
		}
	}
}

func (n *Node) finalize(summary *blockSummary) {
	err := n.localStorage.NodeDB().Finalize(n.ctx, []mkvsNode.Root{
		summary.IORoot,
		summary.StateRoot,
	})
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
	default:
		n.logger.Error("failed to finalize storage round",
			"err", err,
			"round", summary.Round,
		)
	}

	n.finalizeCh <- summary
}

type inFlight struct {
	outstanding   outstandingMask
	awaitingRetry outstandingMask
}

func (n *Node) initGenesis(rt *registryApi.Runtime, genesisBlock *block.Block) error {
	n.logger.Info("initializing storage at genesis")

	// Check what the latest finalized version in the database is as we may be using a database
	// from a previous version or network.
	latestVersion, err := n.localStorage.NodeDB().GetLatestVersion(n.ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
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

		if n.localStorage.NodeDB().HasRoot(maybeRoot) {
			n.logger.Debug("latest version earlier than genesis state root, filling in versions",
				"genesis_state_root", genesisBlock.Header.StateRoot,
				"genesis_round", genesisBlock.Header.Round,
				"latest_version", latestVersion,
			)
			for v := latestVersion; v < stateRoot.Version; v++ {
				_, err = n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
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

	// If we are incompatible and the database is not empty, we cannot do anything. If the database
	// is empty we can either apply genesis state from the runtime descriptor (if relevant) or we
	// assume the node will sync from a different node.
	if !compatible && latestVersion > 0 {
		n.logger.Error("existing state is incompatible with runtime genesis state",
			"genesis_state_root", genesisBlock.Header.StateRoot,
			"genesis_round", genesisBlock.Header.Round,
			"latest_version", latestVersion,
		)
		return fmt.Errorf("existing state is incompatible with runtime genesis state")
	}

	// Check if the genesis round in the descriptor matches the current genesis round and if so,
	// whether genesis state exists in the descriptor. Note that the rounds may not match in case a
	// dump/restore of consensus layer state has been performed.
	if genesisBlock.Header.Round == rt.Genesis.Round && rt.Genesis.State != nil {
		var emptyRoot hash.Hash
		emptyRoot.Empty()

		n.logger.Info("applying genesis state",
			"state_root", rt.Genesis.StateRoot,
		)

		_, err := n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
			Namespace: rt.ID,
			RootType:  storageApi.RootTypeState,
			SrcRound:  rt.Genesis.Round,
			SrcRoot:   emptyRoot,
			DstRound:  rt.Genesis.Round,
			DstRoot:   rt.Genesis.StateRoot,
			WriteLog:  rt.Genesis.State,
		})
		if err != nil {
			return fmt.Errorf("failed to apply genesis state: %w", err)
		}
		compatible = true
	}

	if !compatible {
		// Database is empty, so assume the state will be replicated from another node.
		n.logger.Warn("non-empty state root but no state specified, assuming replication",
			"state_root", genesisBlock.Header.StateRoot,
		)
		n.checkpointSyncForced = true
	}
	return nil
}

func (n *Node) flushSyncedState(summary *blockSummary) uint64 {
	n.syncedLock.Lock()
	defer n.syncedLock.Unlock()

	n.syncedState.LastBlock = *summary
	rtID := n.commonNode.Runtime.ID()
	if err := n.stateStore.PutCBOR(rtID[:], &n.syncedState); err != nil {
		n.logger.Error("can't store watcher state to database", "err", err)
	}

	return n.syncedState.LastBlock.Round
}

func (n *Node) updateExternalServicePolicy(rtComputeNodes nodes.NodeDescriptorLookup) {
	// Create new storage gRPC access policy for the current runtime.
	policy := accessctl.NewPolicy()

	// Add policy for configured sentry nodes.
	for _, addr := range n.workerCommonCfg.SentryAddresses {
		sentryNodesPolicy.AddPublicKeyPolicy(&policy, addr.PubKey)
	}

	executorCommitteePolicy.AddRulesForNodeRoles(&policy, rtComputeNodes.GetNodes(), node.RoleComputeWorker)

	// TODO: Query registry only for storage nodes after
	// https://github.com/oasisprotocol/oasis-core/issues/1923 is implemented.
	nodes, err := n.commonNode.Consensus.Registry().GetNodes(n.ctx, consensus.HeightLatest)
	if err != nil {
		n.logger.Error("couldn't get nodes from registry", "err", err)
	}
	if len(nodes) > 0 {
		// Only include storage nodes for our runtime.
		var storageNodes []*node.Node
		for _, nd := range nodes {
			if nd.GetRuntime(n.commonNode.Runtime.ID()) != nil && nd.HasRoles(node.RoleStorageWorker) {
				storageNodes = append(storageNodes, nd)
			}
		}
		storageNodesPolicy.AddRulesForNodeRoles(&policy, storageNodes, node.RoleStorageWorker)
	}

	// Update storage gRPC access policy for the current runtime.
	n.grpcPolicy.SetAccessPolicy(policy, n.commonNode.Runtime.ID())
	n.logger.Debug("set new storage gRPC access policy", "policy", policy)
}

func (n *Node) runtimeNodesWatcher() {
	defer close(n.rtWatcherQuitCh)

	// Watch registry for runtime node updates and update external gRPC policies.
	// Policy updates are made on:
	// * any updates to the runtime executor committee nodes
	// * any updates to the registered storage nodes for the runtime
	//   (this includes nodes not in committee)

	n.logger.Info("starting runtime nodes watcher")

	committeeNodes := nodes.NewFilteredNodeLookup(
		n.commonNode.Group.Nodes(),
		nodes.TagFilter(committee.TagForCommittee(scheduler.KindComputeExecutor)),
	)
	// Start watching compute node updates for the current committee.
	committeeNodeUps, committeeNodeUpsSub, err := committeeNodes.WatchNodeUpdates()
	if err != nil {
		n.logger.Error("failed to subscribe to node updates",
			"err", err,
		)
		return
	}
	defer committeeNodeUpsSub.Close()

	// Watch registered storage node updates for the runtime.
	storageNodeUps, storageNodeUpsSub, err := n.storageNodes.WatchNodeUpdates()
	if err != nil {
		n.logger.Error("failed to subscribe to node storage node updates",
			"err", err,
		)
		return
	}
	defer storageNodeUpsSub.Close()

	for {
		select {
		case <-n.ctx.Done():
			return
		case u := <-committeeNodeUps:
			if u.Update == nil {
				continue
			}
			// Update policy (handled bellow).
		case u := <-storageNodeUps:
			if u.Update == nil {
				continue
			}
			// Update policy (handled bellow).
		}
		n.updateExternalServicePolicy(committeeNodes)
	}
}

func (n *Node) watchQuit() {
	// Close quit channel on any worker quitting.
	select {
	case <-n.workerQuitCh:
	case <-n.rtWatcherQuitCh:
	}
	close(n.quitCh)
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

	// Start runtime node watcher.
	go n.runtimeNodesWatcher()

	n.logger.Info("starting committee node")

	genesisBlock, err := n.commonNode.Consensus.RootHash().GetGenesisBlock(n.ctx, n.commonNode.Runtime.ID(), consensus.HeightLatest)
	if err != nil {
		n.logger.Error("can't retrieve genesis block", "err", err)
		return
	}
	n.undefinedRound = genesisBlock.Header.Round - 1

	var fetcherGroup sync.WaitGroup

	n.syncedLock.RLock()
	cachedLastRound := n.syncedState.LastBlock.Round
	n.syncedLock.RUnlock()
	if cachedLastRound == defaultUndefinedRound || cachedLastRound < genesisBlock.Header.Round {
		cachedLastRound = n.undefinedRound
	}

	// Initialize genesis from the runtime descriptor.
	if cachedLastRound == n.undefinedRound {
		var rt *registryApi.Runtime
		rt, err = n.commonNode.Runtime.RegistryDescriptor(n.ctx)
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
		n.checkpointer.NotifyNewVersion(genesisBlock.Header.Round)
		n.checkpointer.Flush()
	}

	n.logger.Info("worker initialized",
		"genesis_round", genesisBlock.Header.Round,
		"last_synced", cachedLastRound,
	)

	outOfOrderDiffs := &outOfOrderRoundQueue{}
	outOfOrderApplieds := &outOfOrderRoundQueue{}
	syncingRounds := make(map[uint64]*inFlight)
	hashCache := make(map[uint64]*blockSummary)
	lastFullyAppliedRound := cachedLastRound

	heap.Init(outOfOrderDiffs)

	// We are now ready to service requests.
	registeredCh := make(chan interface{})
	n.roleProvider.SetAvailableWithCallback(func(nd *node.Node) error {
		nd.AddOrUpdateRuntime(n.commonNode.Runtime.ID())
		return nil
	}, func(ctx context.Context) error {
		close(registeredCh)
		return nil
	})

	// Wait for the registration to finish, because we'll need to ask
	// questions immediately.
	n.logger.Debug("waiting for node registration to finish")
	select {
	case <-registeredCh:
	case <-n.ctx.Done():
		return
	}

	// Try to perform initial sync from state and io checkpoints.
	if !n.checkpointSyncDisabled || n.checkpointSyncForced {
		var (
			summary *blockSummary
			attempt int
		)
	CheckpointSyncRetry:
		for {
			summary, err = n.syncCheckpoints()
			if err == nil {
				break
			}

			attempt++
			switch n.checkpointSyncForced {
			case true:
				// We have no other options but to perform a checkpoint sync as we are missing
				// genesis state.
				n.logger.Info("checkpoint sync required as we don't have genesis state, retrying",
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
			cachedLastRound = n.flushSyncedState(summary)
			lastFullyAppliedRound = cachedLastRound
			n.logger.Info("checkpoint sync succeeded",
				logging.LogEvent, LogEventCheckpointSyncSuccess,
			)
		}
	}
	close(n.initCh)

	// Main processing loop. When a new block comes in, its state and io roots are inspected and their
	// writelogs fetched from remote storage nodes in case we don't have them locally yet. Fetches are
	// asynchronous and, once complete, trigger local Apply operations. These are serialized
	// per round (all applies for a given round have to be complete before applying anyting for following
	// rounds) using the outOfOrderDiffs priority queue and outOfOrderApplieds. Once a round has all its write
	// logs applied, a Finalize for it is triggered, again serialized by round but otherwise asynchronous
	// (outOfOrderApplieds and cachedLastRound).
mainLoop:
	for {
		// Drain the Apply and Finalize queues first, before waiting for new events in the select
		// below. Applies are drained first, followed by finalizations (which are asynchronous
		// but serialized, i.e. only one Finalize can be in progress at a time).

		// Apply any writelogs that came in through fetchDiff, but only if they are for the round
		// after the last fully applied one (lastFullyAppliedRound).
		if len(*outOfOrderDiffs) > 0 && lastFullyAppliedRound+1 == (*outOfOrderDiffs)[0].GetRound() {
			lastDiff := heap.Pop(outOfOrderDiffs).(*fetchedDiff)
			// Apply the write log if one exists.
			if lastDiff.fetched {
				_, err = n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
					Namespace: lastDiff.thisRoot.Namespace,
					RootType:  lastDiff.thisRoot.Type,
					SrcRound:  lastDiff.prevRoot.Version,
					SrcRoot:   lastDiff.prevRoot.Hash,
					DstRound:  lastDiff.thisRoot.Version,
					DstRoot:   lastDiff.thisRoot.Hash,
					WriteLog:  lastDiff.writeLog,
				})
				if err != nil {
					n.logger.Error("can't apply write log",
						"err", err,
						"old_root", lastDiff.prevRoot,
						"new_root", lastDiff.thisRoot,
					)
				}
			}

			// Check if we have fully synced the given round. If we have, we can proceed
			// with the Finalize operation.
			syncing := syncingRounds[lastDiff.round]
			syncing.outstanding &= ^lastDiff.fetchMask
			if syncing.outstanding == maskNone && syncing.awaitingRetry == maskNone {
				n.logger.Debug("finished syncing round", "round", lastDiff.round)
				delete(syncingRounds, lastDiff.round)
				summary := hashCache[lastDiff.round]
				delete(hashCache, lastDiff.round-1)

				storageWorkerLastSyncedRound.With(n.getMetricLabels()).Set(float64(lastDiff.round))

				// Finalize storage for this round. This happens asynchronously
				// with respect to Apply operations for subsequent rounds.
				lastFullyAppliedRound = lastDiff.round
				heap.Push(outOfOrderApplieds, summary)
			}

			continue
		}

		// Check if any new rounds were fully applied and need to be finalized. Only finalize
		// if it's the round after the one that was finalized last (cachedLastRound).
		// The finalization happens asynchronously with respect to this worker loop and any
		// applies that happen for subsequent rounds (which can proceed while earlier rounds are
		// still finalizing).
		if len(*outOfOrderApplieds) > 0 && cachedLastRound+1 == (*outOfOrderApplieds)[0].GetRound() {
			lastSummary := heap.Pop(outOfOrderApplieds).(*blockSummary)
			fetcherGroup.Add(1)
			go func() {
				defer fetcherGroup.Done()
				n.finalize(lastSummary)
			}()
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

			if _, ok := hashCache[lastFullyAppliedRound]; !ok && lastFullyAppliedRound == n.undefinedRound {
				dummy := blockSummary{
					Namespace: blk.Header.Namespace,
					Round:     lastFullyAppliedRound + 1,
				}
				dummy.IORoot.Empty()
				dummy.IORoot.Version = lastFullyAppliedRound + 1
				dummy.StateRoot.Empty()
				dummy.StateRoot.Version = lastFullyAppliedRound + 1
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
				oldBlock, err = n.commonNode.Runtime.History().GetBlock(n.ctx, i)
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

			for i := lastFullyAppliedRound + 1; i <= blk.Header.Round; i++ {
				syncing, ok := syncingRounds[i]
				if ok && syncing.outstanding == maskAll {
					continue
				}

				if !ok {
					syncing = &inFlight{
						outstanding:   maskNone,
						awaitingRetry: maskAll,
					}
					syncingRounds[i] = syncing

					if i == blk.Header.Round {
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
				prevIORoot := mkvsNode.Root{ // IO roots aren't chained, so clear it (but leave cache intact).
					Namespace: this.IORoot.Namespace,
					Version:   this.IORoot.Version,
					Type:      mkvsNode.RootTypeIO,
				}
				prevIORoot.Hash.Empty()

				if (syncing.outstanding&maskIO) == 0 && (syncing.awaitingRetry&maskIO) != 0 {
					syncing.outstanding |= maskIO
					syncing.awaitingRetry &= ^maskIO
					fetcherGroup.Add(1)
					n.fetchPool.Submit(func() {
						defer fetcherGroup.Done()
						n.fetchDiff(this.Round, &prevIORoot, &this.IORoot, maskIO)
					})
				}
				if (syncing.outstanding&maskState) == 0 && (syncing.awaitingRetry&maskState) != 0 {
					syncing.outstanding |= maskState
					syncing.awaitingRetry &= ^maskState
					fetcherGroup.Add(1)
					n.fetchPool.Submit(func() {
						defer fetcherGroup.Done()
						n.fetchDiff(this.Round, &prev.StateRoot, &this.StateRoot, maskState)
					})
				}
			}

		case item := <-n.diffCh:
			if item.err != nil {
				n.logger.Error("error calling getdiff",
					"err", item.err,
					"round", item.round,
					"old_root", item.prevRoot,
					"new_root", item.thisRoot,
					"fetch_mask", item.fetchMask,
					"fetched", item.fetched,
				)
				syncingRounds[item.round].outstanding &= ^item.fetchMask
				syncingRounds[item.round].awaitingRetry |= item.fetchMask
			} else {
				heap.Push(outOfOrderDiffs, item)
			}

		case finalized := <-n.finalizeCh:
			// No further sync or out of order handling needed here, since
			// only one finalize at a time is triggered (for round cachedLastRound+1)
			cachedLastRound = n.flushSyncedState(finalized)
			storageWorkerLastFullRound.With(n.getMetricLabels()).Set(float64(finalized.Round))

			// Notify the checkpointer that there is a new finalized round.
			if n.checkpointer != nil {
				n.checkpointer.NotifyNewVersion(finalized.Round)
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
