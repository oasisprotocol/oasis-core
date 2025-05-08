// Package full implements a full CometBFT consensus node.
package full

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtconfig "github.com/cometbft/cometbft/config"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtlight "github.com/cometbft/cometbft/light"
	cmtmempool "github.com/cometbft/cometbft/mempool"
	cmtnode "github.com/cometbft/cometbft/node"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtproxy "github.com/cometbft/cometbft/proxy"
	cmtcli "github.com/cometbft/cometbft/rpc/client/local"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstatesync "github.com/cometbft/cometbft/statesync"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/random"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
	"github.com/oasisprotocol/oasis-core/go/consensus/metrics"
	"github.com/oasisprotocol/oasis-core/go/consensus/pricediscovery"
	cmflags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// Time difference threshold used when considering if node is done with
	// initial syncing. If difference is greater than the specified threshold
	// the node is considered not yet synced.
	// NOTE: this is only used during the initial sync.
	syncWorkerLastBlockTimeDiffThreshold = 1 * time.Minute

	minUpgradeStopWaitPeriod = 5 * time.Second

	// tmSubscriberID is the subscriber identifier used for all internal CometBFT pubsub
	// subscriptions. If any other subscriber IDs need to be derived they will be under this prefix.
	tmSubscriberID = "oasis-core"

	exportsSubDir = "exports"
)

var (
	_ consensusAPI.Backend = (*fullService)(nil)

	labelCometBFT = prometheus.Labels{"backend": "cometbft"}
)

// Config contains configuration parameters for the full node.
type Config struct {
	CommonConfig

	// TimeoutCommit specifies the duration to wait after committing a block
	// before starting a new height.
	TimeoutCommit time.Duration
	// SkipTimeoutCommit determines whether to proceed immediately once all
	// precommits are received.
	SkipTimeoutCommit bool
	// EmptyBlockInterval defines the time interval between empty blocks.
	EmptyBlockInterval time.Duration

	// Upgrader manages software upgrades.
	Upgrader upgradeAPI.Backend
}

// fullService implements a full CometBFT node.
type fullService struct { // nolint: maligned
	sync.Mutex
	*commonNode

	p2p p2pAPI.Service

	upgrader      upgradeAPI.Backend
	node          *cmtnode.Node
	client        *cmtcli.Local
	blockNotifier *pubsub.Broker
	failMonitor   *failMonitor

	submissionMgr consensusAPI.SubmissionManager

	timeoutCommit      time.Duration
	skipTimeoutCommit  bool
	emptyBlockInterval time.Duration

	syncedCh chan struct{}
	quitCh   chan struct{}

	startFn  func() error
	stopOnce sync.Once

	nextSubscriberID uint64
}

// Implements consensusAPI.Backend.
func (t *fullService) Start() error {
	if t.started() {
		return fmt.Errorf("cometbft: service already started")
	}

	switch t.initialized() {
	case true:
		if err := t.commonNode.start(); err != nil {
			return err
		}
		if err := t.startFn(); err != nil {
			return err
		}
		if err := t.node.Start(); err != nil {
			return fmt.Errorf("cometbft: failed to start service: %w", err)
		}

		// Make sure the quit channel is closed when the node shuts down.
		go func() {
			select {
			case <-t.quitCh:
			case <-t.node.Quit():
				select {
				case <-t.quitCh:
				default:
					close(t.quitCh)
				}
			}
		}()

		// Start event dispatchers for all the service clients.
		t.serviceClientsWg.Add(len(t.serviceClients))
		for _, svc := range t.serviceClients {
			go func() {
				defer t.serviceClientsWg.Done()
				t.serviceClientWorker(t.ctx, svc)
			}()
		}
		// Start sync checker.
		go t.syncWorker()
		// Start block notifier.
		go t.blockNotifierWorker()
		// Optionally start metrics updater.
		if cmmetrics.Enabled() {
			go t.metrics()
		}
	case false:
		close(t.syncedCh)
	}

	t.commonNode.finishStart()

	return nil
}

// Implements consensusAPI.Backend.
func (t *fullService) Quit() <-chan struct{} {
	return t.quitCh
}

// Implements consensusAPI.Backend.
func (t *fullService) Stop() {
	if !t.initialized() || !t.started() {
		return
	}

	t.stopOnce.Do(func() {
		t.failMonitor.markCleanShutdown()
		if err := t.node.Stop(); err != nil {
			t.Logger.Error("Error on stopping node", err)
		}

		t.commonNode.stop()
	})
}

// Implements consensusAPI.Backend.
func (t *fullService) Synced() <-chan struct{} {
	return t.syncedCh
}

// Implements consensusAPI.Backend.
func (t *fullService) SupportedFeatures() consensusAPI.FeatureMask {
	return consensusAPI.FeatureServices | consensusAPI.FeatureFullNode
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	if _, err := t.submitTx(ctx, tx); err != nil {
		return err
	}
	return nil
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmitTxNoWait(_ context.Context, tx *transaction.SignedTransaction) error {
	return t.broadcastTxRaw(cbor.Marshal(tx))
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	data, err := t.submitTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	tps, err := t.GetTransactionsWithProofs(ctx, data.Height)
	if err != nil {
		return nil, err
	}

	if data.Index >= uint32(len(tps.Transactions)) {
		return nil, fmt.Errorf("cometbft: invalid transaction index")
	}

	return &transaction.Proof{
		Height:   data.Height,
		RawProof: tps.Proofs[data.Index],
	}, nil
}

func (t *fullService) submitTx(ctx context.Context, tx *transaction.SignedTransaction) (*cmttypes.EventDataTx, error) {
	// Subscribe to the transaction being included in a block.
	data := cbor.Marshal(tx)
	query := cmttypes.EventQueryTxFor(data)
	subID := t.newSubscriberID()
	txSub, err := t.subscribe(subID, query)
	if err != nil {
		return nil, err
	}
	if ptrSub, ok := txSub.(*cometbftPubsubBuffer).tmSubscription.(*cmtpubsub.Subscription); ok && ptrSub == nil {
		t.Logger.Debug("broadcastTx: service has shut down. Cancel our context to recover")
		<-ctx.Done()
		return nil, ctx.Err()
	}

	defer t.unsubscribe(subID, query) // nolint: errcheck

	// Subscribe to the transaction becoming invalid.
	txHash := hash.NewFromBytes(data)

	recheckCh, recheckSub, err := t.mux.WatchInvalidatedTx(txHash)
	if err != nil {
		return nil, err
	}
	defer recheckSub.Close()

	// First try to broadcast.
	if err := t.broadcastTxRaw(data); err != nil {
		return nil, err
	}

	// Wait for the transaction to be included in a block.
	select {
	case v := <-recheckCh:
		return nil, v
	case v := <-txSub.Out():
		data := v.Data().(cmttypes.EventDataTx)
		if result := data.Result; !result.IsOK() {
			return nil, errors.FromCode(result.GetCodespace(), result.GetCode(), result.GetLog())
		}
		return &data, nil
	case <-txSub.Cancelled():
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *fullService) broadcastTxRaw(data []byte) error {
	// We could use t.client.BroadcastTxSync but that is annoying as it
	// doesn't give you the right fields when CheckTx fails.
	mp := t.node.Mempool()

	// Submit the transaction to mempool and wait for response.
	ch := make(chan *cmtabcitypes.Response, 1)
	err := mp.CheckTx(cmttypes.Tx(data), func(rsp *cmtabcitypes.Response) {
		ch <- rsp
		close(ch)
	}, cmtmempool.TxInfo{})
	switch err {
	case nil:
	case cmtmempool.ErrTxInCache:
		// Transaction already in the mempool or was recently there.
		return consensusAPI.ErrDuplicateTx
	default:
		return fmt.Errorf("cometbft: failed to submit to local mempool: %w", err)
	}

	rsp := <-ch
	if result := rsp.GetCheckTx(); !result.IsOK() {
		return errors.FromCode(result.GetCodespace(), result.GetCode(), result.GetLog())
	}

	return nil
}

func (t *fullService) newSubscriberID() string {
	return fmt.Sprintf("%s/subscriber-%d", tmSubscriberID, atomic.AddUint64(&t.nextSubscriberID, 1))
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	var protoEv cmtproto.Evidence
	if err := protoEv.Unmarshal(evidence.Meta); err != nil {
		return fmt.Errorf("cometbft: malformed evidence while unmarshalling: %w", err)
	}

	ev, err := cmttypes.EvidenceFromProto(&protoEv)
	if err != nil {
		return fmt.Errorf("cometbft: malformed evidence while converting: %w", err)
	}

	if _, err := t.client.BroadcastEvidence(ctx, ev); err != nil {
		return fmt.Errorf("cometbft: broadcast evidence failed: %w", err)
	}

	return nil
}

func (t *fullService) subscribe(subscriber string, query cmtpubsub.Query) (cmttypes.Subscription, error) {
	// Note: The CometBFT documentation claims using SubscribeUnbuffered can
	// freeze the server, however, the buffered Subscribe can drop events, and
	// force-unsubscribe the channel if processing takes too long.

	subFn := func() (cmttypes.Subscription, error) {
		sub, err := t.node.EventBus().SubscribeUnbuffered(t.ctx, subscriber, query)
		if err != nil {
			return nil, err
		}
		// Oh yes, this can actually return a nil subscription even though the
		// error was also nil if the node is just shutting down.
		if sub == (*cmtpubsub.Subscription)(nil) {
			return nil, context.Canceled
		}
		return newCometBFTPubsubBuffer(sub), nil
	}

	if t.started() {
		return subFn()
	}

	// The node doesn't exist until it's started since, creating the node
	// triggers replay, InitChain, and etc.
	t.Logger.Debug("Subscribe: node not available yet, blocking",
		"subscriber", subscriber,
		"query", query,
	)

	// XXX/yawning: As far as I can tell just blocking here is safe as
	// ever single consumer of the API subscribes from a go routine.
	select {
	case <-t.startedCh:
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	}

	return subFn()
}

func (t *fullService) unsubscribe(subscriber string, query cmtpubsub.Query) error {
	if t.started() {
		return t.node.EventBus().Unsubscribe(t.ctx, subscriber, query)
	}

	return fmt.Errorf("cometbft: unsubscribe called with no backing service")
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmissionManager() consensusAPI.SubmissionManager {
	return t.submissionMgr
}

// Implements consensusAPI.Backend.
func (t *fullService) GetUnconfirmedTransactions(context.Context) ([][]byte, error) {
	mempoolTxs := t.node.Mempool().ReapMaxTxs(-1)
	txs := make([][]byte, 0, len(mempoolTxs))
	for _, v := range mempoolTxs {
		txs = append(txs, v[:])
	}
	return txs, nil
}

// Implements consensusAPI.Backend.
func (t *fullService) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status, err := t.commonNode.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	status.Status = consensusAPI.StatusStateSyncing
	status.Features = t.SupportedFeatures()

	status.P2P = &consensusAPI.P2PStatus{}
	status.P2P.PubKey = t.identity.P2PSigner.Public()
	if status.P2P.Addresses, err = t.GetAddresses(); err != nil {
		return nil, err
	}

	if t.started() {
		// Check if node is synced.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.Synced():
			status.Status = consensusAPI.StatusStateReady
		default:
		}

		// List of consensus peers.
		tmpeers := t.node.Switch().Peers().List()
		peers := make([]string, 0, len(tmpeers))
		for _, tmpeer := range tmpeers {
			p := string(tmpeer.ID()) + "@" + tmpeer.RemoteAddr().String()
			peers = append(peers, p)
		}

		status.P2P.Peers = peers
		status.P2P.PeerID = string(t.node.NodeInfo().ID())
	}

	return status, nil
}

// Implements consensusAPI.Backend.
func (t *fullService) GetNextBlockState(ctx context.Context) (*consensusAPI.NextBlockState, error) {
	if !t.started() {
		return nil, fmt.Errorf("cometbft: not yet started")
	}

	rs := t.node.ConsensusState().GetRoundState()
	nbs := &consensusAPI.NextBlockState{
		Height:        rs.Height,
		NumValidators: uint64(rs.Validators.Size()),
		VotingPower:   uint64(rs.Validators.TotalVotingPower()),
	}

	for i, val := range rs.Validators.Validators {
		vote := consensusAPI.Vote{
			VotingPower: uint64(val.VotingPower),
		}

		valNode, err := t.Registry().GetNodeByConsensusAddress(ctx, &registryAPI.ConsensusAddressQuery{
			Height:  rs.Height,
			Address: val.Address,
		})
		switch err {
		case nil:
			vote.NodeID = valNode.ID
			vote.EntityID = valNode.EntityID
			vote.EntityAddress = stakingAPI.NewAddress(valNode.EntityID)
		default:
		}

		if prevote := rs.Votes.Prevotes(rs.Round).GetByIndex(int32(i)); prevote != nil {
			nbs.Prevotes.Votes = append(nbs.Prevotes.Votes, vote)
			nbs.Prevotes.VotingPower = nbs.Prevotes.VotingPower + vote.VotingPower
		}
		if precommit := rs.Votes.Precommits(rs.Round).GetByIndex(int32(i)); precommit != nil {
			nbs.Precommits.Votes = append(nbs.Precommits.Votes, vote)
			nbs.Precommits.VotingPower = nbs.Precommits.VotingPower + vote.VotingPower
		}
	}
	nbs.Prevotes.Ratio = float64(nbs.Prevotes.VotingPower) / float64(nbs.VotingPower)
	nbs.Precommits.Ratio = float64(nbs.Precommits.VotingPower) / float64(nbs.VotingPower)

	return nbs, nil
}

// Implements consensusAPI.Backend.
func (t *fullService) RegisterP2PService(p2p p2pAPI.Service) error {
	t.Lock()
	defer t.Unlock()
	if t.p2p != nil {
		return fmt.Errorf("p2p service already registered")
	}
	t.p2p = p2p

	return nil
}

// Implements consensusAPI.Backend.
func (t *fullService) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	ch, sub, err := t.WatchCometBFTBlocks()
	if err != nil {
		return nil, nil, err
	}
	mapCh := make(chan *consensusAPI.Block)
	go func() {
		defer close(mapCh)

		for {
			select {
			case tmBlk, ok := <-ch:
				if !ok {
					return
				}

				mapCh <- api.NewBlock(tmBlk)
			case <-ctx.Done():
				return
			}
		}
	}()

	return mapCh, sub, nil
}

// WatchCometBFTBlocks returns a stream of CometBFT blocks as they are
// returned via the `EventDataNewBlock` query.
func (t *fullService) WatchCometBFTBlocks() (<-chan *cmttypes.Block, *pubsub.Subscription, error) {
	ch := make(chan *cmttypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (t *fullService) lazyInit() error { // nolint: gocyclo
	if t.initialized() {
		return nil
	}

	var err error

	// Create CometBFT application mux.
	var pruneCfg abci.PruneConfig
	pruneStrat := config.GlobalConfig.Consensus.Prune.Strategy
	if err = pruneCfg.Strategy.FromString(pruneStrat); err != nil {
		return err
	}
	pruneCfg.NumKept = config.GlobalConfig.Consensus.Prune.NumKept
	pruneCfg.PruneInterval = max(config.GlobalConfig.Consensus.Prune.Interval, time.Second)

	appConfig := &abci.ApplicationConfig{
		DataDir:                   filepath.Join(t.dataDir, tmcommon.StateDir),
		StorageBackend:            config.GlobalConfig.Storage.Backend,
		Pruning:                   pruneCfg,
		HaltEpoch:                 beaconAPI.EpochTime(config.GlobalConfig.Consensus.HaltEpoch),
		HaltHeight:                config.GlobalConfig.Consensus.HaltHeight,
		MinGasPrice:               config.GlobalConfig.Consensus.MinGasPrice,
		Identity:                  t.identity,
		DisableCheckpointer:       config.GlobalConfig.Consensus.Checkpointer.Disabled,
		CheckpointerCheckInterval: config.GlobalConfig.Consensus.Checkpointer.CheckInterval,
		InitialHeight:             uint64(t.genesisHeight),
		ChainContext:              t.chainContext,
	}
	t.mux, err = abci.NewApplicationServer(t.ctx, t.upgrader, appConfig)
	if err != nil {
		return err
	}

	// CometBFT needs the on-disk directories to be present when
	// launched like this, so create the relevant sub-directories
	// under the node DataDir.
	cometbftDataDir := filepath.Join(t.dataDir, tmcommon.StateDir)
	if err = tmcommon.InitDataDir(cometbftDataDir); err != nil {
		return err
	}

	// Convert addresses and public keys to CometBFT form.
	persistentPeers, err := tmcommon.ConsensusAddressesToCometBFT(config.GlobalConfig.Consensus.P2P.PersistentPeer)
	if err != nil {
		return fmt.Errorf("cometbft: failed to convert persistent peer addresses: %w", err)
	}
	seeds, err := tmcommon.ConsensusAddressesToCometBFT(config.GlobalConfig.P2P.Seeds)
	if err != nil {
		return fmt.Errorf("cometbft: failed to convert seed addresses: %w", err)
	}
	sentryUpstreamAddrs, err := tmcommon.ConsensusAddressesToCometBFT(config.GlobalConfig.Consensus.SentryUpstreamAddresses)
	if err != nil {
		return fmt.Errorf("cometbft: failed to convert sentry upstream addresses: %w", err)
	}
	unconditionalPeers, err := tmcommon.PublicKeysToCometBFT(config.GlobalConfig.Consensus.P2P.UnconditionalPeer)
	if err != nil {
		return fmt.Errorf("cometbft: failed to convert unconditional peer public keys: %w", err)
	}

	// Create CometBFT node.
	cometConfig := cmtconfig.DefaultConfig()
	_ = viper.Unmarshal(&cometConfig)
	cometConfig.SetRoot(cometbftDataDir)
	cometConfig.Consensus.TimeoutCommit = t.timeoutCommit
	cometConfig.Consensus.SkipTimeoutCommit = t.skipTimeoutCommit
	cometConfig.Consensus.CreateEmptyBlocks = true
	cometConfig.Consensus.CreateEmptyBlocksInterval = t.emptyBlockInterval
	cometConfig.Consensus.DebugUnsafeReplayRecoverCorruptedWAL = config.GlobalConfig.Consensus.Debug.UnsafeReplayRecoverCorruptedWAL && cmflags.DebugDontBlameOasis()
	cometConfig.Mempool.Version = cmtconfig.MempoolV1
	cometConfig.Instrumentation.Prometheus = true
	cometConfig.Instrumentation.PrometheusListenAddr = ""
	cometConfig.TxIndex.Indexer = "null"
	cometConfig.P2P.ListenAddress = config.GlobalConfig.Consensus.ListenAddress
	cometConfig.P2P.ExternalAddress = config.GlobalConfig.Consensus.ExternalAddress
	cometConfig.P2P.PexReactor = !config.GlobalConfig.Consensus.P2P.DisablePeerExchange
	cometConfig.P2P.MaxNumInboundPeers = config.GlobalConfig.Consensus.P2P.MaxNumInboundPeers
	cometConfig.P2P.MaxNumOutboundPeers = config.GlobalConfig.Consensus.P2P.MaxNumOutboundPeers
	cometConfig.P2P.SendRate = config.GlobalConfig.Consensus.P2P.SendRate
	cometConfig.P2P.RecvRate = config.GlobalConfig.Consensus.P2P.RecvRate
	cometConfig.P2P.PersistentPeers = strings.Join(persistentPeers, ",")
	cometConfig.P2P.PersistentPeersMaxDialPeriod = config.GlobalConfig.Consensus.P2P.PersistenPeersMaxDialPeriod
	cometConfig.P2P.UnconditionalPeerIDs = strings.Join(unconditionalPeers, ",")
	cometConfig.P2P.Seeds = strings.Join(seeds, ",")
	cometConfig.P2P.AddrBookStrict = !(config.GlobalConfig.Consensus.Debug.P2PAddrBookLenient && cmflags.DebugDontBlameOasis())
	cometConfig.P2P.AllowDuplicateIP = config.GlobalConfig.Consensus.Debug.P2PAllowDuplicateIP && cmflags.DebugDontBlameOasis()
	cometConfig.RPC.ListenAddress = ""

	if len(sentryUpstreamAddrs) > 0 {
		t.Logger.Info("Acting as a cometbft sentry", "addrs", sentryUpstreamAddrs)

		// Append upstream addresses to persistent, private and unconditional peers.
		cometConfig.P2P.PersistentPeers += "," + strings.Join(sentryUpstreamAddrs, ",")

		var sentryUpstreamIDs []string
		for _, addr := range sentryUpstreamAddrs {
			parts := strings.Split(addr, "@")
			if len(parts) != 2 {
				return fmt.Errorf("malformed sentry upstream address: %s", addr)
			}
			sentryUpstreamIDs = append(sentryUpstreamIDs, parts[0])
		}

		sentryUpstreamIDsStr := strings.Join(sentryUpstreamIDs, ",")
		cometConfig.P2P.PrivatePeerIDs += "," + sentryUpstreamIDsStr
		cometConfig.P2P.UnconditionalPeerIDs += "," + sentryUpstreamIDsStr
	}

	if !cometConfig.P2P.PexReactor {
		t.Logger.Info("pex reactor disabled",
			logging.LogEvent, api.LogEventPeerExchangeDisabled,
		)
	}

	cometbftPV, err := crypto.LoadOrGeneratePrivVal(cometbftDataDir, t.identity.ConsensusSigner)
	if err != nil {
		return err
	}

	cometbftGenesisProvider := func() (*cmttypes.GenesisDoc, error) {
		return t.genesisDoc, nil
	}

	dbProvider, err := db.GetProvider()
	if err != nil {
		t.Logger.Error("failed to obtain database provider",
			"err", err,
		)
		return err
	}

	// HACK: Wrap the provider so we can extract the state database handle. This is required because
	// CometBFT does not expose a way to access the state database and we need it to bypass some
	// stupid things like pagination on the in-process "client".
	wrapDbProvider := func(dbCtx *cmtnode.DBContext) (dbm.DB, error) {
		rawDB, derr := dbProvider(dbCtx)
		if derr != nil {
			return nil, derr
		}
		db := db.WithCloser(rawDB, t.dbCloser)

		switch dbCtx.ID {
		case "state":
			// CometBFT state database.
			t.stateStore = cmtstate.NewStore(db, cmtstate.StoreOptions{})
		case "blockstore":
			// CometBFT blockstore database.
			t.blockStoreDB = db
		default:
		}

		return db, nil
	}

	// HACK: cmtnode.NewNode() triggers block replay and or ABCI chain
	// initialization, instead of t.node.Start().  This is a problem
	// because at the time that lazyInit() is called, none of the ABCI
	// applications are registered.
	//
	// Defer actually initializing the node till after everything
	// else is setup.
	t.startFn = func() (err error) {
		defer func() {
			// The node constructor can panic early in case an error occurs during block replay as
			// the fail monitor is not yet initialized in that case. Propagate the error.
			if p := recover(); p != nil {
				switch pt := p.(type) {
				case error:
					err = pt
				default:
					err = fmt.Errorf("%v", pt)
				}
			}
		}()

		// Configure state sync if enabled.
		var stateProvider cmtstatesync.StateProvider
		if config.GlobalConfig.Consensus.StateSync.Enabled {
			t.Logger.Info("state sync enabled")

			t.Lock()
			if t.p2p == nil {
				t.Unlock()
				t.Logger.Info("failed to create state sync client", "err", "p2p disabled")
				return fmt.Errorf("failed to create state sync client: p2p disabled")
			}
			t.Unlock()

			// Enable state sync in the configuration.
			cometConfig.StateSync.Enable = true
			cometConfig.StateSync.TrustHash = config.GlobalConfig.Consensus.LightClient.Trust.Hash

			// Create new state sync state provider.
			cfg := light.Config{
				GenesisDocument: t.genesisDoc,
				TrustOptions: cmtlight.TrustOptions{
					Period: config.GlobalConfig.Consensus.LightClient.Trust.Period,
					Height: int64(config.GlobalConfig.Consensus.LightClient.Trust.Height),
					Hash:   cometConfig.StateSync.TrustHashBytes(),
				},
			}
			lightClient, err := light.NewClient(t.ctx, t.chainContext, t.p2p, cfg)
			if err != nil {
				t.Logger.Error("failed to create light client",
					"err", err,
				)
				return fmt.Errorf("failed to create light client: %w", err)
			}
			stateProvider = newStateProvider(t.chainContext, t.genesisHeight, lightClient)
		}

		t.node, err = cmtnode.NewNode(cometConfig,
			cometbftPV,
			&cmtp2p.NodeKey{PrivKey: crypto.SignerToCometBFT(t.identity.P2PSigner)},
			cmtproxy.NewLocalClientCreator(t.mux.Mux()),
			cometbftGenesisProvider,
			wrapDbProvider,
			cmtnode.DefaultMetricsProvider(cometConfig.Instrumentation),
			tmcommon.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug),
			cmtnode.StateProvider(stateProvider),
		)
		if err != nil {
			return fmt.Errorf("cometbft: failed to create node: %w", err)
		}
		if t.stateStore == nil {
			// Sanity check for the above wrapDbProvider hack in case the DB provider changes.
			return fmt.Errorf("cometbft: internal error: state database not set")
		}
		t.client = cmtcli.New(t.node)
		t.failMonitor = newFailMonitor(t.ctx, t.Logger, t.node.ConsensusState().Wait)

		hooks := []api.HaltHook{
			t.upgradeHaltHook(),
			t.dumpGenesisHaltHook(),
		}
		for _, hook := range hooks {
			t.mux.RegisterHaltHook(hook)
		}

		return nil
	}

	return nil
}

func (t *fullService) syncWorker() {
	checkSyncFn := func() (isSyncing bool, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("cometbft: node disappeared, terminated?")
			}
		}()

		return t.node.ConsensusReactor().WaitSync(), nil
	}

	for {
		select {
		case <-t.node.Quit():
			return
		case <-time.After(1 * time.Second):
			isFastSyncing, err := checkSyncFn()
			if err != nil {
				t.Logger.Error("Failed to poll FastSync",
					"err", err,
				)
				return
			}
			if !isFastSyncing {
				// Check latest block time.
				tmBlock, err := t.GetCometBFTBlock(t.ctx, consensusAPI.HeightLatest)
				if err != nil {
					t.Logger.Error("Failed to get cometbft block",
						"err", err,
					)
					return
				}

				if tmBlock == nil {
					continue
				}

				now := time.Now()
				// Latest block within threshold.
				if now.Sub(tmBlock.Header.Time) < syncWorkerLastBlockTimeDiffThreshold {
					t.Logger.Info("CometBFT Node finished initial sync")
					close(t.syncedCh)
					return
				}

				t.Logger.Debug("Node still syncing",
					"currentTime", now,
					"latestBlockTime", tmBlock.Time,
					"diff", now.Sub(tmBlock.Time),
				)
			}
		}
	}
}

func (t *fullService) blockNotifierWorker() {
	subscriber := newEventSubscriber(cmttypes.EventQueryNewBlock, t.node.EventBus())
	handle := func(_ context.Context, msg cmtpubsub.Message) {
		switch ev := msg.Data().(type) {
		case cmttypes.EventDataNewBlock:
			t.blockNotifier.Broadcast(ev.Block)
		default:
		}
	}
	if err := subscriber.process(t.ctx, handle); err != nil {
		t.Logger.Error("event processing failed", "err", err)
	}
}

// metrics updates oasis_consensus metrics by checking last accepted block info.
func (t *fullService) metrics() {
	ch, sub, err := t.WatchCometBFTBlocks()
	if err != nil {
		return
	}
	defer sub.Close()

	// CometBFT uses specific public key encoding.
	pubKey := t.identity.ConsensusSigner.Public()
	myAddr := []byte(crypto.PublicKeyToCometBFT(&pubKey).Address())
	for {
		var blk *cmttypes.Block
		select {
		case <-t.node.Quit():
			return
		case blk = <-ch:
		}

		// Was block proposed by our node.
		if bytes.Equal(myAddr, blk.ProposerAddress) {
			metrics.ProposedBlocks.With(labelCometBFT).Inc()
		}

		// Was block voted for by our node. Ignore if there was no previous block.
		if blk.LastCommit != nil {
			for _, sig := range blk.LastCommit.Signatures {
				if sig.Absent() || sig.BlockIDFlag == cmttypes.BlockIDFlagNil {
					// Vote is missing, ignore.
					continue
				}

				if bytes.Equal(myAddr, sig.ValidatorAddress) {
					metrics.SignedBlocks.With(labelCometBFT).Inc()
					break
				}
			}
		}
	}
}

// upgradeHaltHook returns a halt hook that handles upgrades gracefully.
func (t *fullService) upgradeHaltHook() api.HaltHook {
	return func(_ context.Context, _ int64, _ beaconAPI.EpochTime, err error) {
		if !errors.Is(err, upgradeAPI.ErrStopForUpgrade) {
			return
		}

		// Mark this as a clean shutdown and request the node to stop gracefully.
		t.failMonitor.markCleanShutdown()

		// Wait before stopping to give time for P2P messages to propagate. Sleep for at least
		// minUpgradeStopWaitPeriod or the configured commit timeout.
		t.Logger.Info("waiting a bit before stopping the node for upgrade")
		waitPeriod := minUpgradeStopWaitPeriod
		if tc := t.timeoutCommit; tc > waitPeriod {
			waitPeriod = tc
		}
		time.Sleep(waitPeriod)

		go func() {
			// Sleep another period so there is some time between when consensus shuts down and
			// when all the other services start shutting down.
			//
			// Randomize the period so that not all nodes shut down at the same time.
			delay := random.GetRandomValueFromInterval(0.5, rand.Float64(), config.GlobalConfig.Consensus.UpgradeStopDelay)
			time.Sleep(delay)

			t.Logger.Info("stopping the node for upgrade")
			t.Stop()

			// Close the quit channel early to force the node to stop. This is needed because
			// the CometBFT node will otherwise never quit.
			close(t.quitCh)
		}()
	}
}

// dumpGenesisHaltHook returns a halt hook which dump genesis.
func (t *fullService) dumpGenesisHaltHook() api.HaltHook {
	return func(ctx context.Context, height int64, epoch beaconAPI.EpochTime, _ error) {
		t.Logger.Info("consensus halt hook: dumping genesis",
			"epoch", epoch,
			"height", height,
		)
		if err := t.dumpGenesis(ctx, height); err != nil {
			t.Logger.Error("halt hook: failed to dump genesis",
				"err", err,
			)
			return
		}
		t.Logger.Info("consensus halt hook: genesis dumped",
			"epoch", epoch,
			"height", height,
		)
	}
}

// dumpGenesis writes state at the given height to a genesis file.
func (t *fullService) dumpGenesis(ctx context.Context, height int64) error {
	doc, err := t.StateToGenesis(ctx, height)
	if err != nil {
		return fmt.Errorf("dumpGenesis: failed to get genesis: %w", err)
	}

	exportsDir := filepath.Join(t.dataDir, exportsSubDir)

	if err := common.Mkdir(exportsDir); err != nil {
		return fmt.Errorf("dumpGenesis: failed to create exports dir: %w", err)
	}

	filename := filepath.Join(exportsDir, fmt.Sprintf("genesis-%s-at-%d.json", doc.ChainID, doc.Height))
	if err := doc.WriteFileJSON(filename); err != nil {
		return fmt.Errorf("dumpGenesis: failed to write genesis file: %w", err)
	}

	return nil
}

// New creates a new CometBFT consensus backend.
func New(ctx context.Context, cfg Config) (consensusAPI.Service, error) {
	commonNode := newCommonNode(ctx, cfg.CommonConfig)

	t := &fullService{
		commonNode:         commonNode,
		upgrader:           cfg.Upgrader,
		blockNotifier:      pubsub.NewBroker(false),
		timeoutCommit:      cfg.TimeoutCommit,
		skipTimeoutCommit:  cfg.SkipTimeoutCommit,
		emptyBlockInterval: cfg.EmptyBlockInterval,
		syncedCh:           make(chan struct{}),
		quitCh:             make(chan struct{}),
	}
	// Common node needs access to parent struct for initializing consensus services.
	t.commonNode.parentNode = t

	t.Logger.Info("starting a full consensus node")

	// Create price discovery mechanism and the submission manager.
	pd, err := pricediscovery.New(ctx, t, config.GlobalConfig.Consensus.Submission.GasPrice)
	if err != nil {
		return nil, fmt.Errorf("failed to create price discovery: %w", err)
	}
	t.submissionMgr = consensusAPI.NewSubmissionManager(t, pd,
		config.GlobalConfig.Consensus.Submission.MaxFee,
	)

	if err := t.lazyInit(); err != nil {
		return nil, fmt.Errorf("lazy init: %w", err)
	}

	return t, t.initialize()
}
