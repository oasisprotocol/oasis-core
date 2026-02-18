package committee

import (
	"context"
	"math"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	p2pProtocol "github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
)

// NodeHooks defines a worker's duties at common events.
// These are called from the runtime's common node's worker.
type NodeHooks interface {
	// HandleNewDispatchInfo handles the latest block information and the
	// active runtime descriptor for transaction dispatch.
	HandleNewDispatchInfo(*runtime.DispatchInfo)
	// HandleRuntimeHostEvent handles new runtime host event.
	HandleRuntimeHostEvent(*host.Event)

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
	Consensus        consensus.Service
	LightProvider    consensus.LightProvider
	Group            *Group
	P2P              p2pAPI.Service
	TxPool           txpool.TransactionPool

	services     *service.Group
	roflNotifier *runtimeRegistry.ROFLNotifier

	txTopic string

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	hooks []NodeHooks

	// Status states.
	consensusSynced           uint32
	runtimeRegistryDescriptor uint32
	keymanagerAvailable       uint32
	hostedRuntimeProvisioned  uint32
	historyReindexingDone     uint32
	workersInitialized        uint32
	runtimeSuspended          uint32

	mu           sync.Mutex
	latestRound  uint64
	latestHeight int64

	committeeRound   uint64
	lastBlockInfo    *runtime.BlockInfo
	dispatchInfoCh   chan struct{}
	activeDescriptor *registry.Runtime

	logger         *logging.Logger
	metricsEnabled bool
}

func (n *Node) getStatusState() api.StatusState {
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
	if atomic.LoadUint32(&n.runtimeSuspended) == 1 {
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
	go n.worker()
	if n.metricsEnabled {
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
	n.mu.Lock()
	status := api.Status{
		Status:        n.getStatusState(),
		LatestRound:   n.latestRound,
		LatestHeight:  n.latestHeight,
		SchedulerRank: math.MaxUint64,
	}
	n.mu.Unlock()

	switch activeVersion, err := n.GetHostedRuntime().GetActiveVersion(); err {
	case nil:
		status.ActiveVersion = activeVersion
	default:
	}

	if committeeInfo, ok := n.Group.CommitteeInfo(); ok {
		status.ExecutorRoles = committeeInfo.Roles

		// Include scheduler rank.
		if rank, ok := committeeInfo.Committee.SchedulerRank(status.LatestRound+1, n.Identity.NodeSigner.Public()); ok {
			status.SchedulerRank = rank
		}

		// Include liveness statistics if the node is an executor committee member.
		if committeeInfo.IsMember() {
			rs, err := n.Consensus.RootHash().GetRuntimeState(n.ctx, &roothash.RuntimeRequest{
				RuntimeID: n.Runtime.ID(),
				Height:    consensus.HeightLatest,
			})
			if err == nil && rs.LivenessStatistics != nil {
				status.Liveness = &api.LivenessStatus{
					TotalRounds: rs.LivenessStatistics.TotalRounds,
				}

				for _, index := range committeeInfo.Indices {
					status.Liveness.LiveRounds += rs.LivenessStatistics.LiveRounds[index]
					status.Liveness.FinalizedProposals += rs.LivenessStatistics.FinalizedProposals[index]
					status.Liveness.MissedProposals += rs.LivenessStatistics.MissedProposals[index]
				}
			}
		}
	}

	status.Peers = n.P2P.Peers(n.Runtime.ID())

	status.Host.Versions = n.RuntimeRegistry.GetBundleRegistry().GetVersions(n.Runtime.ID())

	return &status, nil
}

func (n *Node) handleCommitteeTransition(committee *scheduler.Committee) {
	if err := n.Group.CommitteeTransition(n.ctx, committee); err != nil {
		n.logger.Error("unable to handle committee transition",
			"err", err,
		)
	}

	committeeTransitionCount.With(n.getMetricLabels()).Inc()
	epochNumber.With(n.getMetricLabels()).Set(float64(committee.ValidFor))
}

func (n *Node) handleSuspend() {
	n.logger.Warn("runtime has been suspended")

	n.Group.Suspend()
}

func (n *Node) updateHostedRuntimeVersion(rt *registry.Runtime) {
	// Always take the latest epoch to avoid reverting to stale state.
	epoch, err := n.Consensus.Beacon().GetNextEpoch(n.ctx, consensus.HeightLatest)
	if err != nil {
		n.logger.Error("failed to fetch next block epoch",
			"err", err,
		)
		return
	}

	// Update the runtime version based on the currently active deployment.
	activeDeploy := rt.ActiveDeployment(epoch)
	var activeVersion *version.Version
	if activeDeploy != nil {
		activeVersion = &activeDeploy.Version
	}

	// For compute nodes, determine if there is a next version and activate it early.
	var nextVersion *version.Version
	if config.GlobalConfig.Mode == config.ModeCompute {
		nextDeploy := rt.NextDeployment(epoch)
		preWarmEpochs := beacon.EpochTime(config.GlobalConfig.Runtime.PreWarmEpochs)

		if nextDeploy != nil && nextDeploy.ValidFrom-epoch <= preWarmEpochs {
			nextVersion = &nextDeploy.Version
		}
	}

	n.SetHostedRuntimeVersion(activeVersion, nextVersion)

	if _, err := n.GetHostedRuntimeActiveVersion(); err != nil {
		n.logger.Warn("failed to activate runtime version(s)",
			"err", err,
			"version", activeVersion,
			"next_version", nextVersion,
		)
		// This is not fatal and it should result in the node declaring itself unavailable.
	}
}

func (n *Node) handleRuntimeHostEvent(ev *host.Event) {
	n.logger.Debug("got runtime event", "ev", ev)

	switch {
	case ev.Started != nil:
		atomic.StoreUint32(&n.hostedRuntimeProvisioned, 1)
	case ev.FailedToStart != nil, ev.Stopped != nil:
		atomic.StoreUint32(&n.hostedRuntimeProvisioned, 0)
	}

	for _, hooks := range n.hooks {
		hooks.HandleRuntimeHostEvent(ev)
	}
}

func (n *Node) worker() { //nolint: gocyclo
	n.logger.Info("starting committee node")

	var wg sync.WaitGroup
	defer wg.Wait()

	defer close(n.quitCh)
	defer n.cancelCtx()

	// Wait for consensus sync.
	n.logger.Info("delaying worker start until after initial synchronization")
	select {
	case <-n.stopCh:
		return
	case <-n.Consensus.Synced():
	}
	n.logger.Info("consensus has finished initial synchronization")
	atomic.StoreUint32(&n.consensusSynced, 1)

	// Start the transaction pool after consensus is synced.
	if err := n.TxPool.Start(); err != nil {
		n.logger.Error("failed to start transaction pool",
			"err", err,
		)
		return
	}

	// Wait for the runtime.
	rt, err := n.Runtime.RegistryDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to wait for registry descriptor",
			"err", err,
		)
		return
	}
	atomic.StoreUint32(&n.runtimeRegistryDescriptor, 1)

	n.logger.Info("runtime is registered with the registry")

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

	// Wait for for runtime history to be initialized.
	n.logger.Info("waiting for block history to be initialized")
	select {
	case <-n.Runtime.History().Initialized():
	case <-n.stopCh:
		return
	}
	n.logger.Info("block history initialized")
	atomic.StoreUint32(&n.historyReindexingDone, 1)

	// Mark worker as initialized.
	n.logger.Debug("common worker is initialized")
	close(n.initCh)

	// Wait for all child workers to initialize as well.
	n.logger.Debug("waiting for child worker initialization")
	for _, hooks := range n.hooks {
		select {
		case <-hooks.Initialized():
		case <-n.stopCh:
			return
		}
	}
	n.logger.Debug("all child workers are initialized")
	atomic.StoreUint32(&n.workersInitialized, 1)

	// Start watching runtime components so that we can provision new versions
	// once they are discovered.
	bundleRegistry := n.RuntimeRegistry.GetBundleRegistry()
	compCh, compSub := bundleRegistry.WatchComponents(n.Runtime.ID())
	defer compSub.Close()

	// Provision all known components.
	for _, comp := range bundleRegistry.Components(n.Runtime.ID()) {
		if err := n.ProvisionHostedRuntimeComponent(comp); err != nil {
			n.logger.Error("failed to provision runtime component",
				"err", err,
				"id", comp.ID(),
				"version", comp.Version,
			)
			return
		}
	}
	// Start watching runtime committees so we know when the runtime committee
	// changes and can update our worker role accordingly.
	cmCh, cmSub, err := n.Consensus.Scheduler().WatchCommittees(n.ctx)
	if err != nil {
		n.logger.Error("failed to watch committees",
			"err", err,
		)
		return
	}
	defer cmSub.Close()

	// Start watching runtime blocks so we can schedule new transactions and
	// check existing ones based on the latest block and active runtime descriptor.
	blkCh, blkSub, err := n.Consensus.RootHash().WatchBlocks(n.ctx, n.Runtime.ID())
	if err != nil {
		n.logger.Error("failed to watch runtime blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	// Start watching runtime descriptors so we know when to update the hosted
	// runtime version, ensuring we never miss any deployment updates, even if
	// the runtime is suspended.
	rtCh, rtSub, err := n.Runtime.WatchRegistryDescriptor()
	if err != nil {
		n.logger.Error("failed to watch registry descriptor",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	// Perform initial hosted runtime version update to ensure we have something even in cases where
	// initial block processing fails for any reason.
	n.updateHostedRuntimeVersion(rt)

	// Start the runtime.
	hrt := n.GetHostedRuntime()
	hrtEventCh, hrtSub := hrt.WatchEvents()
	defer hrtSub.Close()

	hrt.Start()
	defer hrt.Stop()

	// Start the runtime host notifier and other services.
	wg.Go(func() {
		if err := n.services.Serve(n.ctx); err != nil {
			n.logger.Error("service group stopped", "err", err)
		}
	})

	// Enter the main processing loop.
	for {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case cm := <-cmCh:
			n.handleCommittee(n.ctx, cm)
		case blk := <-blkCh:
			n.handleRuntimeBlock(n.ctx, blk)
		case <-n.dispatchInfoCh:
			n.handleDispatchInfo()
		case ev := <-hrtEventCh:
			// Received a hosted runtime event.
			n.handleRuntimeHostEvent(ev)
		case rt = <-rtCh:
			n.updateHostedRuntimeVersion(rt)
		case compNotify := <-compCh:
			switch {
			case compNotify.Added != nil:
				// Received a new version of a runtime component.
				if err := n.ProvisionHostedRuntimeComponent(compNotify.Added); err != nil {
					n.logger.Error("failed to provision hosted runtime",
						"err", err,
						"id", compNotify.Added.ID(),
						"version", compNotify.Added.Version,
					)
					return
				}

				n.updateHostedRuntimeVersion(rt)
			case compNotify.Removed != nil:
				// Received removal of a component.
				if err := n.RemoveHostedRuntimeComponent(*compNotify.Removed); err != nil {
					n.logger.Error("failed to remove hosted runtime component",
						"err", err,
						"id", *compNotify.Removed,
					)
					return
				}
			}
		}
	}
}

func (n *Node) handleCommittee(ctx context.Context, committee *scheduler.Committee) {
	if committee.Kind != scheduler.KindComputeExecutor {
		return
	}
	if committee.RuntimeID != n.Runtime.ID() {
		return
	}

	rs, err := n.Consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: n.Runtime.ID(),
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		n.logger.Error("failed to get runtime state",
			"err", err,
		)
		return
	}

	n.KeyManagerClient.SetKeyManagerID(rs.Runtime.KeyManager)

	n.updateHostedRuntimeVersion(rs.Runtime)

	switch rs.Suspended {
	case true:
		n.handleSuspend()
		atomic.StoreUint32(&n.runtimeSuspended, 1)
	case false:
		n.handleCommitteeTransition(rs.Committee)
		atomic.StoreUint32(&n.runtimeSuspended, 0)
	}

	n.committeeRound = rs.LastBlock.Header.Round
	n.activeDescriptor = rs.Runtime

	select {
	case n.dispatchInfoCh <- struct{}{}:
	default:
	}
}

func (n *Node) handleRuntimeBlock(ctx context.Context, blk *roothash.AnnotatedBlock) {
	processedBlockCount.With(n.getMetricLabels()).Inc()

	// Update status of the current block.
	n.mu.Lock()
	n.latestRound = blk.Block.Header.Round
	n.latestHeight = blk.Height
	n.mu.Unlock()

	// Track how many rounds have failed.
	if blk.Block.Header.HeaderType == block.RoundFailed {
		n.logger.Warn("round has failed")
		failedRoundCount.With(n.getMetricLabels()).Inc()
	}

	// Fetch light consensus block.
	lb, err := n.Consensus.Core().GetLightBlock(ctx, blk.Height)
	if err != nil {
		n.logger.Error("failed to get light block",
			"err", err,
			"height", blk.Height,
			"round", blk.Block.Header.Round,
		)
		return
	}

	// Fetch incoming messages.
	inMsgs, err := n.Consensus.RootHash().GetIncomingMessageQueue(ctx, &roothash.InMessageQueueRequest{
		RuntimeID: n.Runtime.ID(),
		Height:    blk.Height,
	})
	if err != nil {
		n.logger.Error("failed to get incoming messages",
			"err", err,
			"height", blk.Height,
			"round", blk.Block.Header.Round,
		)
		return
	}

	// Fetch epoch of the latest block.
	epoch, err := n.Consensus.Beacon().GetEpoch(ctx, blk.Height)
	if err != nil {
		n.logger.Error("failed to get epoch",
			"err", err,
			"height", blk.Height,
			"round", blk.Block.Header.Round,
		)
		return
	}

	n.TxPool.ProcessIncomingMessages(inMsgs)

	n.lastBlockInfo = &runtime.BlockInfo{
		RuntimeBlock:     blk.Block,
		ConsensusBlock:   lb,
		IncomingMessages: inMsgs,
		Epoch:            epoch,
	}

	select {
	case n.dispatchInfoCh <- struct{}{}:
	default:
	}
}

func (n *Node) handleDispatchInfo() {
	if n.lastBlockInfo == nil || n.activeDescriptor == nil {
		return
	}

	if n.lastBlockInfo.RuntimeBlock.Header.Round < n.committeeRound {
		return
	}

	di := &runtime.DispatchInfo{
		BlockInfo:        n.lastBlockInfo,
		ActiveDescriptor: n.activeDescriptor,
	}

	n.TxPool.ProcessDispatchInfo(di)

	if n.lastBlockInfo.RuntimeBlock.Header.Round == n.committeeRound {
		n.TxPool.RecheckTxs()
	}

	for _, hooks := range n.hooks {
		hooks.HandleNewDispatchInfo(di)
	}
}

func NewNode(
	chainContext string,
	hostNode control.NodeController,
	runtime runtimeRegistry.Runtime,
	provisioner host.Provisioner,
	rtRegistry runtimeRegistry.Registry,
	identity *identity.Identity,
	keymanager keymanager.Backend,
	consensus consensus.Service,
	lightProvider consensus.LightProvider,
	p2pHost p2pAPI.Service,
	txPoolCfg tpConfig.Config,
	metricsEnabled bool,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Prepare committee group services.
	group, err := NewGroup(ctx, runtime.ID(), identity, consensus, p2pHost)
	if err != nil {
		cancel()
		return nil, err
	}

	txTopic := p2pProtocol.NewTopicKindTxID(chainContext, runtime.ID())

	n := &Node{
		ChainContext:    chainContext,
		HostNode:        hostNode,
		Runtime:         runtime,
		RuntimeRegistry: rtRegistry,
		Identity:        identity,
		KeyManager:      keymanager,
		Consensus:       consensus,
		LightProvider:   lightProvider,
		Group:           group,
		P2P:             p2pHost,
		txTopic:         txTopic,
		ctx:             ctx,
		cancelCtx:       cancel,
		stopCh:          make(chan struct{}),
		quitCh:          make(chan struct{}),
		initCh:          make(chan struct{}),
		dispatchInfoCh:  make(chan struct{}, 1),
		logger:          logging.GetLogger("worker/common/committee").With("runtime_id", runtime.ID()),
		metricsEnabled:  metricsEnabled,
	}

	// Prepare the key manager client wrapper.
	n.KeyManagerClient = NewKeyManagerClientWrapper(p2pHost, consensus, chainContext, n.logger)

	// Prepare the runtime host handler.
	handler := runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.Runtime, consensus)

	// Prepare the runtime host node helpers.
	rhn, err := runtimeRegistry.NewRuntimeHostNode(runtime, provisioner, handler, rtRegistry.GetLogManager())
	if err != nil {
		return nil, err
	}
	n.RuntimeHostNode = rhn

	// Prepare the runtime host notifier.
	host := rhn.GetHostedRuntime()
	notifier := runtimeRegistry.NewRuntimeHostNotifier(host)
	lbNotifier := runtimeRegistry.NewLightBlockNotifier(runtime, host, consensus, notifier)
	kmNotifier := runtimeRegistry.NewKeyManagerNotifier(runtime, host, consensus, notifier)
	n.roflNotifier = runtimeRegistry.NewROFLNotifier(runtime, host, consensus, notifier)

	// Prepare services to run.
	n.services = service.NewGroup(notifier, lbNotifier, kmNotifier, n.roflNotifier)

	// Prepare transaction pool.
	n.TxPool = txpool.New(runtime.ID(), txPoolCfg, rhn.GetHostedRuntime(), runtime.History(), n)

	// Register transaction message handler as that is something that all workers must handle.
	p2pHost.RegisterHandler(txTopic, &txMsgHandler{n})

	// Register transaction sync service.
	p2pHost.RegisterProtocolServer(txsync.NewServer(chainContext, runtime.ID(), n.TxPool))

	return n, nil
}
