package committee

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
	"github.com/oasisprotocol/oasis-core/go/worker/common/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
)

const periodicMetricsInterval = 60 * time.Second

var (
	processedBlockCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_processed_block_count",
			Help: "Number of processed roothash blocks.",
		},
		[]string{"runtime"},
	)
	failedRoundCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_failed_round_count",
			Help: "Number of failed roothash rounds.",
		},
		[]string{"runtime"},
	)
	epochTransitionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_epoch_transition_count",
			Help: "Number of epoch transitions.",
		},
		[]string{"runtime"},
	)
	epochNumber = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_epoch_number",
			Help: "Current epoch number as seen by the worker.",
		},
		[]string{"runtime"},
	)
	workerIsExecutorWorker = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_is_worker",
			Help: "1 if worker is currently an executor worker, 0 otherwise.",
		},
		[]string{"runtime"},
	)
	workerIsExecutorBackup = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_is_backup_worker",
			Help: "1 if worker is currently an executor backup worker, 0 otherwise.",
		},
		[]string{"runtime"},
	)
	executorCommitteeP2PPeers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_committee_p2p_peers",
			Help: "Number of executor committee P2P peers.",
		},
		[]string{"runtime"},
	)
	livenessTotalRounds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_total_rounds",
			Help: "Number of total rounds in last epoch.",
		},
		[]string{"runtime"},
	)
	livenessLiveRounds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_live_rounds",
			Help: "Number of live rounds in last epoch.",
		},
		[]string{"runtime"},
	)
	livenessRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_live_ratio",
			Help: "Ratio between live and total rounds. Reports 1 if node is not in committee.",
		},
		[]string{"runtime"},
	)

	nodeCollectors = []prometheus.Collector{
		processedBlockCount,
		failedRoundCount,
		epochTransitionCount,
		epochNumber,
		// Periodically collected metrics.
		workerIsExecutorWorker,
		workerIsExecutorBackup,
		executorCommitteeP2PPeers,
		livenessTotalRounds,
		livenessLiveRounds,
		livenessRatio,
	}

	metricsOnce sync.Once
)

// NodeHooks defines a worker's duties at common events.
// These are called from the runtime's common node's worker.
type NodeHooks interface {
	// Guarded by CrossNode.
	HandleNewBlockEarlyLocked(*runtime.BlockInfo)
	// Guarded by CrossNode.
	HandleNewBlockLocked(*runtime.BlockInfo)
	// Guarded by CrossNode.
	HandleRuntimeHostEventLocked(*host.Event)

	// Initialized returns a channel that will be closed when the worker is initialized and ready
	// to service requests.
	Initialized() <-chan struct{}
}

// Node is a committee node.
type Node struct {
	*runtimeRegistry.RuntimeHostNode

	ChainContext string

	Runtime         runtimeRegistry.Runtime
	RuntimeRegistry runtimeRegistry.Registry

	HostNode control.NodeController

	Identity         *identity.Identity
	KeyManager       keymanager.Backend
	KeyManagerClient *KeyManagerClientWrapper
	Consensus        consensus.Backend
	LightClient      consensus.LightClient
	Group            *Group
	P2P              p2pAPI.Service
	TxPool           txpool.TransactionPool

	txTopic string

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}
	resumeCh  chan struct{}

	hooks []NodeHooks

	// Status states.
	consensusSynced           uint32
	runtimeRegistryDescriptor uint32
	keymanagerAvailable       uint32
	hostedRuntimeProvisioned  uint32
	historyReindexingDone     uint32
	workersInitialized        uint32

	// Mutable and shared between nodes' workers.
	// Guarded by .CrossNode.
	CrossNode             sync.Mutex
	CurrentBlock          *block.Block
	CurrentBlockHeight    int64
	CurrentConsensusBlock *consensus.LightBlock
	CurrentDescriptor     *registry.Runtime
	CurrentEpoch          beacon.EpochTime

	logger *logging.Logger
}

func (n *Node) getStatusStateLocked() api.StatusState {
	if atomic.LoadUint32(&n.consensusSynced) == 0 {
		return api.StatusStateWaitingConsensusSync
	}
	if atomic.LoadUint32(&n.runtimeRegistryDescriptor) == 0 {
		return api.StatusStateWaitingRuntimeRegistry
	}
	if atomic.LoadUint32(&n.keymanagerAvailable) == 0 {
		return api.StatusStateWaitingKeymanager
	}
	if atomic.LoadUint32(&n.historyReindexingDone) == 0 {
		return api.StatusStateWaitingHistoryReindex
	}
	if atomic.LoadUint32(&n.workersInitialized) == 0 {
		return api.StatusStateWaitingWorkersInit
	}
	if atomic.LoadUint32(&n.hostedRuntimeProvisioned) == 0 {
		return api.StatusStateWaitingHostedRuntime
	}
	// If resumeCh exists the runtime is suspended (safe to check since the cross node lock should be held).
	if n.resumeCh != nil {
		return api.StatusStateRuntimeSuspended
	}

	return api.StatusStateReady
}

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start starts the service.
func (n *Node) Start() error {
	if err := n.Group.Start(); err != nil {
		return fmt.Errorf("failed to start group services: %w", err)
	}

	// Start the transaction pool.
	if err := n.TxPool.Start(); err != nil {
		return fmt.Errorf("failed to start transaction pool: %w", err)
	}

	go n.worker()
	if cmmetrics.Enabled() {
		go n.metricsWorker()
	}

	return nil
}

// Stop halts the service.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		close(n.stopCh)
		n.TxPool.Stop()
		n.KeyManagerClient.SetKeyManagerID(nil)
	})
}

// Quit returns a channel that will be closed when the service terminates.
func (n *Node) Quit() <-chan struct{} {
	return n.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (n *Node) Cleanup() {
}

// Initialized returns a channel that will be closed when the node is
// initialized and ready to service requests.
func (n *Node) Initialized() <-chan struct{} {
	return n.initCh
}

// AddHooks adds a NodeHooks to be called.
// There is no going back.
func (n *Node) AddHooks(hooks NodeHooks) {
	n.hooks = append(n.hooks, hooks)
}

// GetStatus returns the common committee node status.
func (n *Node) GetStatus() (*api.Status, error) {
	n.CrossNode.Lock()
	defer n.CrossNode.Unlock()

	var status api.Status
	status.Status = n.getStatusStateLocked()

	if n.CurrentBlock != nil {
		status.LatestRound = n.CurrentBlock.Header.Round
		status.LatestHeight = n.CurrentBlockHeight
	}

	if n.CurrentDescriptor != nil {
		activeDeploy := n.CurrentDescriptor.ActiveDeployment(n.CurrentEpoch)
		if activeDeploy != nil {
			status.ActiveVersion = &activeDeploy.Version
		}
	}

	status.SchedulerRank = math.MaxUint64

	epoch := n.Group.GetEpochSnapshot()
	if cmte := epoch.GetExecutorCommittee(); cmte != nil {
		status.ExecutorRoles = cmte.Roles

		// Include scheduler rank.
		if rank, ok := cmte.Committee.SchedulerRank(status.LatestRound+1, epoch.identity.NodeSigner.Public()); ok {
			status.SchedulerRank = rank
		}

		// Include liveness statistics if the node is an executor committee member.
		if epoch.IsExecutorMember() {
			rs, err := n.Consensus.RootHash().GetRuntimeState(n.ctx, &roothash.RuntimeRequest{
				RuntimeID: n.Runtime.ID(),
				Height:    consensus.HeightLatest,
			})
			if err == nil && rs.LivenessStatistics != nil {
				status.Liveness = &api.LivenessStatus{
					TotalRounds: rs.LivenessStatistics.TotalRounds,
				}

				for _, index := range cmte.Indices {
					status.Liveness.LiveRounds += rs.LivenessStatistics.LiveRounds[index]
					status.Liveness.FinalizedProposals += rs.LivenessStatistics.FinalizedProposals[index]
					status.Liveness.MissedProposals += rs.LivenessStatistics.MissedProposals[index]
				}
			}
		}
	}

	status.Peers = n.P2P.Peers(n.Runtime.ID())

	status.Host.Versions = n.Runtime.HostVersions()

	return &status, nil
}

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.Runtime.ID().String(),
	}
}

// Guarded by n.CrossNode.
func (n *Node) handleEpochTransitionLocked(height int64) {
	n.logger.Info("epoch transition has occurred")

	epochTransitionCount.With(n.getMetricLabels()).Inc()

	// Transition group.
	if err := n.Group.EpochTransition(n.ctx, height); err != nil {
		n.logger.Error("unable to handle epoch transition",
			"err", err,
		)
	}

	epoch := n.Group.GetEpochSnapshot()

	// Mark all executor nodes in the current committee as important.
	if ec := epoch.GetExecutorCommittee(); ec != nil {
		if pm := n.P2P.PeerManager(); pm != nil {
			if pids, err := p2pAPI.PublicKeyMapToPeerIDs(ec.Peers); err == nil {
				pm.PeerTagger().SetPeerImportance(p2pAPI.ImportantNodeCompute, n.Runtime.ID(), pids)
			}
		}
	}

	epochNumber.With(n.getMetricLabels()).Set(float64(epoch.epochNumber))
}

// Guarded by n.CrossNode.
func (n *Node) handleSuspendLocked(int64) {
	n.logger.Warn("runtime has been suspended")

	// Suspend group.
	n.Group.Suspend()

	// If the runtime has been suspended, we need to switch to checking the latest registry
	// descriptor instead of the active one as otherwise we may miss deployment updates and never
	// register, keeping the runtime suspended.
	if n.resumeCh == nil {
		resumeCh := make(chan struct{})
		n.resumeCh = resumeCh
		go func() {
			ch, sub, _ := n.Runtime.WatchRegistryDescriptor()
			defer sub.Close()

			for {
				select {
				case <-n.stopCh:
					return
				case rt := <-ch:
					// Descriptor update while suspended.
					n.CrossNode.Lock()

					// Make sure we are still suspended.
					if n.resumeCh == nil {
						n.CrossNode.Unlock()
						return
					}

					// Refresh current epoch as otherwise it could be stale which will result in the
					// new runtime version not being activated.
					currentEpoch, err := n.Consensus.Beacon().GetEpoch(n.ctx, consensus.HeightLatest)
					switch err {
					case nil:
						n.CurrentEpoch = currentEpoch
					default:
						n.logger.Error("failed to fetch current epoch",
							"err", err,
						)
					}
					n.CurrentDescriptor = rt

					n.updateHostedRuntimeVersionLocked()
					n.CrossNode.Unlock()
				case <-resumeCh:
					// Runtime no longer suspended, stop.
					return
				}
			}
		}()
	}
}

func (n *Node) updateHostedRuntimeVersionLocked() {
	if n.CurrentDescriptor == nil {
		return
	}

	// Update the runtime version based on the currently active deployment.
	activeDeploy := n.CurrentDescriptor.ActiveDeployment(n.CurrentEpoch)
	// NOTE: If there is no active deployment this will activate the all-zero version which may
	//       result in the runtime stopping.
	var activeVersion version.Version
	if activeDeploy != nil {
		activeVersion = activeDeploy.Version
	}

	// For compute nodes, determine if there is a next version and activate it early.
	var nextVersion *version.Version
	if config.GlobalConfig.Mode == config.ModeCompute {
		nextDeploy := n.CurrentDescriptor.NextDeployment(n.CurrentEpoch)
		preWarmEpochs := beacon.EpochTime(config.GlobalConfig.Runtime.PreWarmEpochs)

		if nextDeploy != nil && nextDeploy.ValidFrom-n.CurrentEpoch <= preWarmEpochs {
			nextVersion = new(version.Version)
			*nextVersion = nextDeploy.Version
		}
	}

	if err := n.SetHostedRuntimeVersion(activeVersion, nextVersion); err != nil {
		n.logger.Error("failed to activate runtime version(s)",
			"err", err,
			"version", activeVersion,
			"next_version", nextVersion,
		)
		// This is not fatal and it should result in the node declaring itself unavailable.
	}
}

// Guarded by n.CrossNode.
func (n *Node) handleNewBlockLocked(blk *block.Block, height int64) {
	processedBlockCount.With(n.getMetricLabels()).Inc()

	header := blk.Header

	// The first received block will be treated an epoch transition (if valid).
	// This will refresh the committee on the first block,
	// instead of waiting for the next epoch transition to occur.
	// Helps in cases where node is restarted mid epoch.
	firstBlockReceived := n.CurrentBlock == nil

	// Fetch light consensus block.
	consensusBlk, err := n.Consensus.GetLightBlock(n.ctx, height)
	if err != nil {
		n.logger.Error("failed to query light block",
			"err", err,
			"height", height,
			"round", blk.Header.Round,
		)
		return
	}

	// Update the current block.
	n.CurrentBlock = blk
	n.CurrentBlockHeight = height
	n.CurrentConsensusBlock = consensusBlk

	// Update active descriptor on epoch transitions.
	if firstBlockReceived || header.HeaderType == block.EpochTransition || header.HeaderType == block.Suspended {
		var rs *roothash.RuntimeState
		rs, err = n.Consensus.RootHash().GetRuntimeState(n.ctx, &roothash.RuntimeRequest{
			RuntimeID: n.Runtime.ID(),
			Height:    height,
		})
		if err != nil {
			n.logger.Error("failed to query runtime state",
				"err", err,
			)
			return
		}
		n.CurrentDescriptor = rs.Runtime

		n.CurrentEpoch, err = n.Consensus.Beacon().GetEpoch(n.ctx, height)
		if err != nil {
			n.logger.Error("failed to fetch current epoch",
				"err", err,
			)
			return
		}

		// Notify suspended runtime watcher to stop.
		if !rs.Suspended && n.resumeCh != nil {
			close(n.resumeCh)
			n.resumeCh = nil
		}

		n.updateHostedRuntimeVersionLocked()

		// Make sure to update the key manager if needed.
		n.KeyManagerClient.SetKeyManagerID(n.CurrentDescriptor.KeyManager)
	}

	bi := &runtime.BlockInfo{
		RuntimeBlock:     n.CurrentBlock,
		ConsensusBlock:   n.CurrentConsensusBlock,
		Epoch:            n.CurrentEpoch,
		ActiveDescriptor: n.CurrentDescriptor,
	}

	for _, hooks := range n.hooks {
		hooks.HandleNewBlockEarlyLocked(bi)
	}

	// Perform actions based on block type.
	switch header.HeaderType {
	case block.Normal:
		if firstBlockReceived {
			n.logger.Warn("forcing an epoch transition on first received block")
			n.handleEpochTransitionLocked(height)
		} else {
			// Normal block.
			n.Group.RoundTransition()
		}
	case block.RoundFailed:
		if firstBlockReceived {
			n.logger.Warn("forcing an epoch transition on first received block")
			n.handleEpochTransitionLocked(height)
		} else {
			// Round has failed.
			n.logger.Warn("round has failed")
			n.Group.RoundTransition()

			failedRoundCount.With(n.getMetricLabels()).Inc()
		}
	case block.EpochTransition:
		// Process an epoch transition.
		n.handleEpochTransitionLocked(height)
	case block.Suspended:
		// Process runtime being suspended.
		n.handleSuspendLocked(height)
	default:
		n.logger.Error("invalid block type",
			"block", bi.RuntimeBlock,
		)
		return
	}

	n.TxPool.ProcessBlock(bi)

	// Fetch incoming messages.
	inMsgs, err := n.Consensus.RootHash().GetIncomingMessageQueue(n.ctx, &roothash.InMessageQueueRequest{
		RuntimeID: n.Runtime.ID(),
		Height:    consensusBlk.Height,
	})
	if err != nil {
		n.logger.Error("failed to query incoming messages",
			"err", err,
			"height", height,
			"round", bi.RuntimeBlock.Header.Round,
		)
		return
	}
	n.TxPool.ProcessIncomingMessages(inMsgs)

	for _, hooks := range n.hooks {
		hooks.HandleNewBlockLocked(bi)
	}
}

// Guarded by n.CrossNode.
func (n *Node) handleRuntimeHostEventLocked(ev *host.Event) {
	n.logger.Debug("got runtime event", "ev", ev)

	switch {
	case ev.Started != nil:
		atomic.StoreUint32(&n.hostedRuntimeProvisioned, 1)
	case ev.FailedToStart != nil, ev.Stopped != nil:
		atomic.StoreUint32(&n.hostedRuntimeProvisioned, 0)
	}

	for _, hooks := range n.hooks {
		hooks.HandleRuntimeHostEventLocked(ev)
	}
}

func (n *Node) worker() {
	n.logger.Info("starting committee node")

	defer close(n.quitCh)
	defer (n.cancelCtx)()

	// Wait for consensus sync.
	n.logger.Info("delaying worker start until after initial synchronization")
	select {
	case <-n.stopCh:
		return
	case <-n.Consensus.Synced():
	}
	n.logger.Info("consensus has finished initial synchronization")
	atomic.StoreUint32(&n.consensusSynced, 1)

	// Wait for the runtime.
	rt, err := n.Runtime.ActiveDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to wait for registry descriptor",
			"err", err,
		)
		return
	}
	atomic.StoreUint32(&n.runtimeRegistryDescriptor, 1)

	n.CurrentEpoch, err = n.Consensus.Beacon().GetEpoch(n.ctx, consensus.HeightLatest)
	if err != nil {
		n.logger.Error("failed to fetch current epoch",
			"err", err,
		)
		return
	}

	n.logger.Info("runtime is registered with the registry")

	// Initialize the CurrentDescriptor to make sure there is one even if the runtime gets
	// suspended.
	n.CurrentDescriptor = rt

	// If the runtime requires a key manager, wait for the key manager to actually become available
	// before processing any requests.
	if rt.KeyManager != nil {
		n.logger.Info("runtime indicates a key manager is required, waiting for it to be ready",
			"keymanager_runtime_id", *rt.KeyManager,
		)

		n.KeyManagerClient.SetKeyManagerID(rt.KeyManager)
		select {
		case <-n.ctx.Done():
			n.logger.Error("failed to wait for key manager",
				"err", err,
			)
			return
		case <-n.KeyManagerClient.Initialized():
		}

		n.logger.Info("runtime has a key manager available")
	}
	atomic.StoreUint32(&n.keymanagerAvailable, 1)

	// Start watching roothash blocks.
	blocks, blocksSub, err := n.Consensus.RootHash().WatchBlocks(n.ctx, n.Runtime.ID())
	if err != nil {
		n.logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	// Provision the hosted runtime.
	hrt, hrtNotifier, err := n.ProvisionHostedRuntime(n.ctx)
	if err != nil {
		n.logger.Error("failed to provision hosted runtime",
			"err", err,
		)
		return
	}

	hrtEventCh, hrtSub := hrt.WatchEvents()
	defer hrtSub.Close()

	hrt.Start()
	defer hrt.Stop()

	hrtNotifier.Start()
	defer hrtNotifier.Stop()

	// Perform initial hosted runtime version update to ensure we have something even in cases where
	// initial block processing fails for any reason.
	n.CrossNode.Lock()
	n.updateHostedRuntimeVersionLocked()
	n.CrossNode.Unlock()

	initialized := false
	for {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case blk := <-blocks:
			// We are initialized after we have received the first block. This makes sure that any
			// history reindexing has been completed.
			if !initialized {
				n.logger.Debug("common worker is initialized")
				atomic.StoreUint32(&n.historyReindexingDone, 1)

				close(n.initCh)
				initialized = true

				// Wait for all child workers to initialize as well.
				n.logger.Debug("waiting for child worker initialization")
				for _, hooks := range n.hooks {
					select {
					case <-hooks.Initialized():
					case <-n.stopCh:
						n.logger.Info("termination requested while waiting for child worker initialization")
						return
					}
				}
				n.logger.Debug("all child workers are initialized")
				atomic.StoreUint32(&n.workersInitialized, 1)
			}

			// Received a block (annotated).
			func() {
				n.CrossNode.Lock()
				defer n.CrossNode.Unlock()
				n.handleNewBlockLocked(blk.Block, blk.Height)
			}()
		case ev := <-hrtEventCh:
			// Received a hosted runtime event.
			func() {
				n.CrossNode.Lock()
				defer n.CrossNode.Unlock()
				n.handleRuntimeHostEventLocked(ev)
			}()
		}
	}
}

func (n *Node) updatePeriodicMetrics() {
	boolToMetricVal := func(b bool) float64 {
		if b {
			return 1.0
		}
		return 0.0
	}

	labels := n.getMetricLabels()

	n.CrossNode.Lock()
	defer n.CrossNode.Unlock()

	n.logger.Debug("updating periodic worker node metrics")

	epoch := n.Group.GetEpochSnapshot()
	cmte := epoch.GetExecutorCommittee()
	if cmte == nil {
		return
	}

	executorCommitteeP2PPeers.With(labels).Set(float64(len(n.P2P.Peers(n.Runtime.ID()))))
	workerIsExecutorWorker.With(labels).Set(boolToMetricVal(epoch.IsExecutorWorker()))
	workerIsExecutorBackup.With(labels).Set(boolToMetricVal(epoch.IsExecutorBackupWorker()))

	if !epoch.IsExecutorMember() {
		// Default to 1 if node is not in committee.
		livenessRatio.With(labels).Set(1.0)
		return
	}

	rs, err := n.Consensus.RootHash().GetRuntimeState(n.ctx, &roothash.RuntimeRequest{
		RuntimeID: n.Runtime.ID(),
		Height:    consensus.HeightLatest,
	})
	if err != nil || rs.LivenessStatistics == nil {
		return
	}

	totalRounds := rs.LivenessStatistics.TotalRounds
	var liveRounds uint64
	for _, index := range cmte.Indices {
		liveRounds += rs.LivenessStatistics.LiveRounds[index]
	}
	livenessTotalRounds.With(labels).Set(float64(totalRounds))
	livenessLiveRounds.With(labels).Set(float64(liveRounds))
	livenessRatio.With(labels).Set(float64(liveRounds) / float64(totalRounds))
}

func (n *Node) metricsWorker() {
	n.logger.Info("delaying metrics worker start until worker is initialized")
	select {
	case <-n.stopCh:
		return
	case <-n.initCh:
	}

	n.logger.Debug("starting metrics worker")

	t := time.NewTicker(periodicMetricsInterval)
	defer t.Stop()

	for {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
		}

		n.updatePeriodicMetrics()
	}
}

func NewNode(
	chainContext string,
	hostNode control.NodeController,
	runtime runtimeRegistry.Runtime,
	rtRegistry runtimeRegistry.Registry,
	identity *identity.Identity,
	keymanager keymanager.Backend,
	consensus consensus.Backend,
	lightClient consensus.LightClient,
	p2pHost p2pAPI.Service,
	txPoolCfg tpConfig.Config,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Prepare committee group services.
	group, err := NewGroup(ctx, identity, runtime, consensus)
	if err != nil {
		cancel()
		return nil, err
	}

	txTopic := protocol.NewTopicKindTxID(chainContext, runtime.ID())

	n := &Node{
		ChainContext:    chainContext,
		HostNode:        hostNode,
		Runtime:         runtime,
		RuntimeRegistry: rtRegistry,
		Identity:        identity,
		KeyManager:      keymanager,
		Consensus:       consensus,
		LightClient:     lightClient,
		Group:           group,
		P2P:             p2pHost,
		txTopic:         txTopic,
		ctx:             ctx,
		cancelCtx:       cancel,
		stopCh:          make(chan struct{}),
		quitCh:          make(chan struct{}),
		initCh:          make(chan struct{}),
		logger:          logging.GetLogger("worker/common/committee").With("runtime_id", runtime.ID()),
	}

	// Prepare the key manager client wrapper.
	n.KeyManagerClient = NewKeyManagerClientWrapper(p2pHost, consensus, chainContext, n.logger)

	// Prepare the runtime host node helpers.
	rhn, err := runtimeRegistry.NewRuntimeHostNode(n)
	if err != nil {
		return nil, err
	}
	n.RuntimeHostNode = rhn

	// Prepare transaction pool.
	txPool, err := txpool.New(runtime.ID(), txPoolCfg, n, runtime.History(), n)
	if err != nil {
		return nil, fmt.Errorf("error creating transaction pool: %w", err)
	}
	n.TxPool = txPool

	// Register transaction message handler as that is something that all workers must handle.
	p2pHost.RegisterHandler(txTopic, &txMsgHandler{n})

	// Register transaction sync service.
	p2pHost.RegisterProtocolServer(txsync.NewServer(chainContext, runtime.ID(), txPool))

	return n, nil
}
