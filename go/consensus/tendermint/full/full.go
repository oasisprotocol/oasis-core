// Package full implements a full Tendermint consensus node.
package full

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmlight "github.com/tendermint/tendermint/light"
	tmmempool "github.com/tendermint/tendermint/mempool"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client/local"
	tmrpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	tmstatesync "github.com/tendermint/tendermint/statesync"
	tmtypes "github.com/tendermint/tendermint/types"
	tmdb "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmservice "github.com/oasisprotocol/oasis-core/go/common/service"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/metrics"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmbackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmflags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	cfgCoreExternalAddress = "consensus.tendermint.core.external_address"

	// CfgABCIPruneStrategy configures the ABCI state pruning strategy.
	CfgABCIPruneStrategy = "consensus.tendermint.abci.prune.strategy"
	// CfgABCIPruneNumKept configures the amount of kept heights if pruning is enabled.
	CfgABCIPruneNumKept = "consensus.tendermint.abci.prune.num_kept"

	// CfgSentryUpstreamAddress defines nodes for which we act as a sentry for.
	CfgSentryUpstreamAddress = "consensus.tendermint.sentry.upstream_address"

	// CfgP2PPersistentPeer configures tendermint's persistent peer(s).
	CfgP2PPersistentPeer = "consensus.tendermint.p2p.persistent_peer"
	// CfgP2PPersistenPeersMaxDialPeriod configures the tendermint's persistent peer max dial period.
	CfgP2PPersistenPeersMaxDialPeriod = "consensus.tendermint.p2p.persistent_peers_max_dial_period"
	// CfgP2PDisablePeerExchange disables tendermint's peer-exchange (Pex) reactor.
	CfgP2PDisablePeerExchange = "consensus.tendermint.p2p.disable_peer_exchange"
	// CfgP2PSeeds configures tendermint's seed node(s).
	CfgP2PSeed = "consensus.tendermint.p2p.seed"
	// CfgP2PMaxNumInboundPeers configures the max number of inbound peers.
	CfgP2PMaxNumInboundPeers = "consensus.tendermint.p2p.max_num_inbound_peers"
	// CfgP2PMaxNumOutboundPeers configures the max number of outbound peers, excluding persistent peers.
	CfgP2PMaxNumOutboundPeers = "consensus.tendermint.p2p.max_num_outbound_peers"
	// CfgP2PSendRate is the rate at which packets can be sent, in bytes/second.
	CfgP2PSendRate = "consensus.tendermint.p2p.send_rate"
	// CfgP2PRecvRate is the rate at which packets can be received, in bytes/second.
	CfgP2PRecvRate = "consensus.tendermint.p2p.recv_rate"
	// CfgP2PUnconditionalPeerIDs configures tendermint's unconditional peer(s).
	CfgP2PUnconditionalPeerIDs = "consensus.tendermint.p2p.unconditional_peer_ids"

	// CfgDebugP2PAddrBookLenient configures allowing non-routable addresses.
	CfgDebugP2PAddrBookLenient = "consensus.tendermint.debug.addr_book_lenient"
	// CfgP2PDebugAllowDuplicateIP allows multiple connections from the same IP.
	CfgDebugP2PAllowDuplicateIP = "consensus.tendermint.debug.allow_duplicate_ip"

	// CfgDebugUnsafeReplayRecoverCorruptedWAL enables the debug and unsafe
	// automatic corrupted WAL recovery during replay.
	CfgDebugUnsafeReplayRecoverCorruptedWAL = "consensus.tendermint.debug.unsafe_replay_recover_corrupted_wal"

	// CfgMinGasPrice configures the minimum gas price for this validator.
	CfgMinGasPrice = "consensus.tendermint.min_gas_price"
	// CfgDebugDisableCheckTx disables CheckTx.
	CfgDebugDisableCheckTx = "consensus.tendermint.debug.disable_check_tx"

	// CfgSupplementarySanityEnabled is the supplementary sanity enabled flag.
	CfgSupplementarySanityEnabled = "consensus.tendermint.supplementarysanity.enabled"
	// CfgSupplementarySanityInterval configures the supplementary sanity check interval.
	CfgSupplementarySanityInterval = "consensus.tendermint.supplementarysanity.interval"

	// CfgConsensusStateSyncEnabled enabled consensus state sync.
	CfgConsensusStateSyncEnabled = "consensus.tendermint.state_sync.enabled"
	// CfgConsensusStateSyncConsensusNode specifies nodes exposing public consensus services which
	// are used to sync a light client.
	CfgConsensusStateSyncConsensusNode = "consensus.tendermint.state_sync.consensus_node"
	// CfgConsensusStateSyncTrustPeriod is the light client trust period.
	CfgConsensusStateSyncTrustPeriod = "consensus.tendermint.state_sync.trust_period"
	// CfgConsensusStateSyncTrustHeight is the known trusted height for the light client.
	CfgConsensusStateSyncTrustHeight = "consensus.tendermint.state_sync.trust_height"
	// CfgConsensusStateSyncTrustHash is the known trusted block header hash for the light client.
	CfgConsensusStateSyncTrustHash = "consensus.tendermint.state_sync.trust_hash"
)

const (
	// Time difference threshold used when considering if node is done with
	// initial syncing. If difference is greater than the specified threshold
	// the node is considered not yet synced.
	// NOTE: this is only used during the initial sync.
	syncWorkerLastBlockTimeDiffThreshold = 1 * time.Minute

	// tmSubscriberID is the subscriber identifier used for all internal Tendermint pubsub
	// subscriptions. If any other subscriber IDs need to be derived they will be under this prefix.
	tmSubscriberID = "oasis-core"
)

var (
	_ api.Backend = (*fullService)(nil)

	labelTendermint = prometheus.Labels{"backend": "tendermint"}

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// fullService implements a full Tendermint node.
type fullService struct { // nolint: maligned
	sync.Mutex
	commonNode

	upgrader      upgradeAPI.Backend
	node          *tmnode.Node
	client        *tmcli.Local
	blockNotifier *pubsub.Broker
	failMonitor   *failMonitor

	submissionMgr consensusAPI.SubmissionManager

	genesisProvider genesisAPI.Provider
	isStarted       bool
	startedCh       chan struct{}
	syncedCh        chan struct{}
	quitCh          chan struct{}

	startFn  func() error
	stopOnce sync.Once

	nextSubscriberID uint64
}

func (t *fullService) started() bool {
	t.Lock()
	defer t.Unlock()

	return t.isStarted
}

// Implements service.BackgroundService.
func (t *fullService) Start() error {
	if t.started() {
		return fmt.Errorf("tendermint: service already started")
	}

	switch t.initialized() {
	case true:
		if err := t.commonNode.Start(); err != nil {
			return err
		}
		if err := t.startFn(); err != nil {
			return err
		}
		if err := t.node.Start(); err != nil {
			return fmt.Errorf("tendermint: failed to start service: %w", err)
		}

		// Start event dispatchers for all the service clients.
		t.serviceClientsWg.Add(len(t.serviceClients))
		for _, svc := range t.serviceClients {
			go t.serviceClientWorker(t.ctx, svc)
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

	t.Lock()
	t.isStarted = true
	t.Unlock()

	close(t.startedCh)

	return nil
}

// Implements service.BackgroundService.
func (t *fullService) Quit() <-chan struct{} {
	return t.quitCh
}

// Implements service.BackgroundService.
func (t *fullService) Stop() {
	if !t.initialized() || !t.started() {
		return
	}

	t.stopOnce.Do(func() {
		t.failMonitor.markCleanShutdown()
		if err := t.node.Stop(); err != nil {
			t.Logger.Error("Error on stopping node", err)
		}

		t.commonNode.Stop()
	})
}

func (t *fullService) Started() <-chan struct{} {
	return t.startedCh
}

func (t *fullService) Synced() <-chan struct{} {
	return t.syncedCh
}

func (t *fullService) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	// Subscribe to the transaction being included in a block.
	data := cbor.Marshal(tx)
	query := tmtypes.EventQueryTxFor(data)
	subID := t.newSubscriberID()
	txSub, err := t.subscribe(subID, query)
	if err != nil {
		return err
	}
	if ptrSub, ok := txSub.(*tendermintPubsubBuffer).tmSubscription.(*tmpubsub.Subscription); ok && ptrSub == nil {
		t.Logger.Debug("broadcastTx: service has shut down. Cancel our context to recover")
		<-ctx.Done()
		return ctx.Err()
	}

	defer t.unsubscribe(subID, query) // nolint: errcheck

	// Subscribe to the transaction becoming invalid.
	txHash := hash.NewFromBytes(data)

	recheckCh, recheckSub, err := t.mux.WatchInvalidatedTx(txHash)
	if err != nil {
		return err
	}
	defer recheckSub.Close()

	// First try to broadcast.
	if err := t.broadcastTxRaw(data); err != nil {
		return err
	}

	// Wait for the transaction to be included in a block.
	select {
	case v := <-recheckCh:
		return v
	case v := <-txSub.Out():
		if result := v.Data().(tmtypes.EventDataTx).Result; !result.IsOK() {
			err := errors.FromCode(result.GetCodespace(), result.GetCode())
			if err == nil {
				// Fallback to an ordinary error.
				err = fmt.Errorf(result.GetLog())
			}
			return err
		}
		return nil
	case <-txSub.Cancelled():
		return context.Canceled
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *fullService) broadcastTxRaw(data []byte) error {
	// We could use t.client.BroadcastTxSync but that is annoying as it
	// doesn't give you the right fields when CheckTx fails.
	mp := t.node.Mempool()

	// Submit the transaction to mempool and wait for response.
	ch := make(chan *tmabcitypes.Response, 1)
	err := mp.CheckTx(tmtypes.Tx(data), func(rsp *tmabcitypes.Response) {
		ch <- rsp
		close(ch)
	}, tmmempool.TxInfo{})
	switch err {
	case nil:
	case tmmempool.ErrTxInCache:
		// Transaction already in the mempool or was recently there.
		return consensusAPI.ErrDuplicateTx
	default:
		return fmt.Errorf("tendermint: failed to submit to local mempool: %w", err)
	}

	rsp := <-ch
	if result := rsp.GetCheckTx(); !result.IsOK() {
		err := errors.FromCode(result.GetCodespace(), result.GetCode())
		if err == nil {
			// Fallback to an ordinary error.
			err = fmt.Errorf(result.GetLog())
		}
		return err
	}

	return nil
}

func (t *fullService) newSubscriberID() string {
	return fmt.Sprintf("%s/subscriber-%d", tmSubscriberID, atomic.AddUint64(&t.nextSubscriberID, 1))
}

func (t *fullService) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	var protoEv tmproto.Evidence
	if err := protoEv.Unmarshal(evidence.Meta); err != nil {
		return fmt.Errorf("tendermint: malformed evidence while unmarshalling: %w", err)
	}

	ev, err := tmtypes.EvidenceFromProto(&protoEv)
	if err != nil {
		return fmt.Errorf("tendermint: malformed evidence while converting: %w", err)
	}

	if _, err := t.client.BroadcastEvidence(ev); err != nil {
		return fmt.Errorf("tendermint: broadcast evidence failed: %w", err)
	}

	return nil
}

func (t *fullService) subscribe(subscriber string, query tmpubsub.Query) (tmtypes.Subscription, error) {
	// Note: The tendermint documentation claims using SubscribeUnbuffered can
	// freeze the server, however, the buffered Subscribe can drop events, and
	// force-unsubscribe the channel if processing takes too long.

	subFn := func() (tmtypes.Subscription, error) {
		sub, err := t.node.EventBus().SubscribeUnbuffered(t.ctx, subscriber, query)
		if err != nil {
			return nil, err
		}
		// Oh yes, this can actually return a nil subscription even though the
		// error was also nil if the node is just shutting down.
		if sub == (*tmpubsub.Subscription)(nil) {
			return nil, context.Canceled
		}
		return newTendermintPubsubBuffer(sub), nil
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

func (t *fullService) unsubscribe(subscriber string, query tmpubsub.Query) error {
	if t.started() {
		return t.node.EventBus().Unsubscribe(t.ctx, subscriber, query)
	}

	return fmt.Errorf("tendermint: unsubscribe called with no backing service")
}

func (t *fullService) SubmissionManager() consensusAPI.SubmissionManager {
	return t.submissionMgr
}

func (t *fullService) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	mempoolTxs := t.node.Mempool().ReapMaxTxs(-1)
	txs := make([][]byte, 0, len(mempoolTxs))
	for _, v := range mempoolTxs {
		txs = append(txs, v[:])
	}
	return txs, nil
}

func (t *fullService) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	ch, sub, err := t.WatchTendermintBlocks()
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

func (t *fullService) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status, err := t.commonNode.GetStatus(ctx)
	if err != nil {
		return nil, err
	}

	if t.started() {
		// List of consensus peers.
		tmpeers := t.node.Switch().Peers().List()
		peers := make([]string, 0, len(tmpeers))
		for _, tmpeer := range tmpeers {
			p := string(tmpeer.ID()) + "@" + tmpeer.RemoteAddr().String()
			peers = append(peers, p)
		}
		status.NodePeers = peers
	}

	return status, nil
}

func (t *fullService) ensureStarted(ctx context.Context) error {
	// Make sure that the Tendermint service has started so that we
	// have the client interface available.
	select {
	case <-t.startedCh:
	case <-t.ctx.Done():
		return t.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (t *fullService) WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription, error) {
	typedCh := make(chan *tmtypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (t *fullService) lazyInit() error {
	if t.initialized() {
		return nil
	}

	var err error

	// Create Tendermint application mux.
	var pruneCfg abci.PruneConfig
	pruneStrat := viper.GetString(CfgABCIPruneStrategy)
	if err = pruneCfg.Strategy.FromString(pruneStrat); err != nil {
		return err
	}
	pruneCfg.NumKept = viper.GetUint64(CfgABCIPruneNumKept)

	appConfig := &abci.ApplicationConfig{
		DataDir:         filepath.Join(t.dataDir, tmcommon.StateDir),
		StorageBackend:  db.GetBackendName(),
		Pruning:         pruneCfg,
		HaltEpochHeight: t.genesis.HaltEpoch,
		MinGasPrice:     viper.GetUint64(CfgMinGasPrice),
		OwnTxSigner:     t.identity.NodeSigner.Public(),
		DisableCheckTx:  viper.GetBool(CfgDebugDisableCheckTx) && cmflags.DebugDontBlameOasis(),
		InitialHeight:   uint64(t.genesis.Height),
	}
	t.mux, err = abci.NewApplicationServer(t.ctx, t.upgrader, appConfig)
	if err != nil {
		return err
	}

	// Tendermint needs the on-disk directories to be present when
	// launched like this, so create the relevant sub-directories
	// under the node DataDir.
	tendermintDataDir := filepath.Join(t.dataDir, tmcommon.StateDir)
	if err = tmcommon.InitDataDir(tendermintDataDir); err != nil {
		return err
	}

	// Create Tendermint node.
	tenderConfig := tmconfig.DefaultConfig()
	_ = viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(tendermintDataDir)
	timeoutCommit := t.genesis.Consensus.Parameters.TimeoutCommit
	emptyBlockInterval := t.genesis.Consensus.Parameters.EmptyBlockInterval
	tenderConfig.Consensus.TimeoutCommit = timeoutCommit
	tenderConfig.Consensus.SkipTimeoutCommit = t.genesis.Consensus.Parameters.SkipTimeoutCommit
	tenderConfig.Consensus.CreateEmptyBlocks = true
	tenderConfig.Consensus.CreateEmptyBlocksInterval = emptyBlockInterval
	tenderConfig.Consensus.DebugUnsafeReplayRecoverCorruptedWAL = viper.GetBool(CfgDebugUnsafeReplayRecoverCorruptedWAL) && cmflags.DebugDontBlameOasis()
	tenderConfig.Instrumentation.Prometheus = true
	tenderConfig.Instrumentation.PrometheusListenAddr = ""
	tenderConfig.TxIndex.Indexer = "null"
	tenderConfig.P2P.ListenAddress = viper.GetString(tmcommon.CfgCoreListenAddress)
	tenderConfig.P2P.ExternalAddress = viper.GetString(cfgCoreExternalAddress)
	tenderConfig.P2P.PexReactor = !viper.GetBool(CfgP2PDisablePeerExchange)
	tenderConfig.P2P.MaxNumInboundPeers = viper.GetInt(CfgP2PMaxNumInboundPeers)
	tenderConfig.P2P.MaxNumOutboundPeers = viper.GetInt(CfgP2PMaxNumOutboundPeers)
	tenderConfig.P2P.SendRate = viper.GetInt64(CfgP2PSendRate)
	tenderConfig.P2P.RecvRate = viper.GetInt64(CfgP2PRecvRate)
	// Persistent peers need to be lowercase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparison to validate public keys.
	// Since persistent peers is expected to be in comma-delimited ID@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.PersistentPeers = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PPersistentPeer), ","))
	tenderConfig.P2P.PersistentPeersMaxDialPeriod = viper.GetDuration(CfgP2PPersistenPeersMaxDialPeriod)
	// Unconditional peer IDs need to be lowercase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparison to validate public keys.
	// Since persistent peers is expected to be in comma-delimited ID format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.UnconditionalPeerIDs = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PUnconditionalPeerIDs), ","))
	// Seed Ids need to be lowercase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparison to validate public keys.
	// Since Seeds is expected to be in comma-delimited ID@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.Seeds = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PSeed), ","))
	tenderConfig.P2P.AddrBookStrict = !(viper.GetBool(CfgDebugP2PAddrBookLenient) && cmflags.DebugDontBlameOasis())
	tenderConfig.P2P.AllowDuplicateIP = viper.GetBool(CfgDebugP2PAllowDuplicateIP) && cmflags.DebugDontBlameOasis()
	tenderConfig.RPC.ListenAddress = ""

	sentryUpstreamAddrs := viper.GetStringSlice(CfgSentryUpstreamAddress)
	if len(sentryUpstreamAddrs) > 0 {
		t.Logger.Info("Acting as a tendermint sentry", "addrs", sentryUpstreamAddrs)

		// Append upstream addresses to persistent, private and unconditional peers.
		tenderConfig.P2P.PersistentPeers += "," + strings.ToLower(strings.Join(sentryUpstreamAddrs, ","))

		var sentryUpstreamIDs []string
		for _, addr := range sentryUpstreamAddrs {
			parts := strings.Split(addr, "@")
			if len(parts) != 2 {
				return fmt.Errorf("malformed sentry upstream address: %s", addr)
			}
			sentryUpstreamIDs = append(sentryUpstreamIDs, parts[0])
		}

		// Convert upstream node IDs to lowercase (like other IDs) since
		// Tendermint stores them in a map and uses a case sensitive string
		// comparison to check ID equality.
		sentryUpstreamIDsStr := strings.ToLower(strings.Join(sentryUpstreamIDs, ","))
		tenderConfig.P2P.PrivatePeerIDs += "," + sentryUpstreamIDsStr
		tenderConfig.P2P.UnconditionalPeerIDs += "," + sentryUpstreamIDsStr
	}

	if !tenderConfig.P2P.PexReactor {
		t.Logger.Info("pex reactor disabled",
			logging.LogEvent, api.LogEventPeerExchangeDisabled,
		)
	}

	tendermintPV, err := crypto.LoadOrGeneratePrivVal(tendermintDataDir, t.identity.ConsensusSigner)
	if err != nil {
		return err
	}

	tmGenDoc, err := api.GetTendermintGenesisDocument(t.genesisProvider)
	if err != nil {
		t.Logger.Error("failed to obtain genesis document",
			"err", err,
		)
		return err
	}
	tendermintGenesisProvider := func() (*tmtypes.GenesisDoc, error) {
		return tmGenDoc, nil
	}

	dbProvider, err := db.GetProvider()
	if err != nil {
		t.Logger.Error("failed to obtain database provider",
			"err", err,
		)
		return err
	}

	// HACK: Wrap the provider so we can extract the state database handle. This is required because
	// Tendermint does not expose a way to access the state database and we need it to bypass some
	// stupid things like pagination on the in-process "client".
	wrapDbProvider := func(dbCtx *tmnode.DBContext) (tmdb.DB, error) {
		db, derr := dbProvider(dbCtx)
		if derr != nil {
			return nil, derr
		}

		switch dbCtx.ID {
		case "state":
			// Tendermint state database.
			t.stateStore = db
		case "blockstore":
			t.blockStoreDB = db
		default:
		}

		return db, nil
	}

	// Configure state sync if enabled.
	var stateProvider tmstatesync.StateProvider
	if viper.GetBool(CfgConsensusStateSyncEnabled) {
		t.Logger.Info("state sync enabled")

		// Enable state sync in the configuration.
		tenderConfig.StateSync.Enable = true
		tenderConfig.StateSync.TrustHash = viper.GetString(CfgConsensusStateSyncTrustHash)

		// Create new state sync state provider.
		cfg := light.ClientConfig{
			GenesisDocument: tmGenDoc,
			TrustOptions: tmlight.TrustOptions{
				Period: viper.GetDuration(CfgConsensusStateSyncTrustPeriod),
				Height: int64(viper.GetUint64(CfgConsensusStateSyncTrustHeight)),
				Hash:   tenderConfig.StateSync.TrustHashBytes(),
			},
		}
		for _, rawAddr := range viper.GetStringSlice(CfgConsensusStateSyncConsensusNode) {
			var addr node.TLSAddress
			if err = addr.UnmarshalText([]byte(rawAddr)); err != nil {
				return fmt.Errorf("failed to parse state sync consensus node address (%s): %w", rawAddr, err)
			}

			cfg.ConsensusNodes = append(cfg.ConsensusNodes, addr)
		}
		if stateProvider, err = newStateProvider(t.ctx, cfg); err != nil {
			t.Logger.Error("failed to create state sync state provider",
				"err", err,
			)
			return fmt.Errorf("failed to create state sync state provider: %w", err)
		}
	}

	// HACK: tmnode.NewNode() triggers block replay and or ABCI chain
	// initialization, instead of t.node.Start().  This is a problem
	// because at the time that lazyInit() is called, none of the ABCI
	// applications are registered.
	//
	// Defer actually initializing the node till after everything
	// else is setup.
	t.startFn = func() (err error) {
		defer func() {
			// The node constructor can panic early in case an error occurrs during block replay as
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

		t.node, err = tmnode.NewNode(tenderConfig,
			tendermintPV,
			&tmp2p.NodeKey{PrivKey: crypto.SignerToTendermint(t.identity.P2PSigner)},
			tmproxy.NewLocalClientCreator(t.mux.Mux()),
			tendermintGenesisProvider,
			wrapDbProvider,
			tmnode.DefaultMetricsProvider(tenderConfig.Instrumentation),
			tmcommon.NewLogAdapter(!viper.GetBool(tmcommon.CfgLogDebug)),
			tmnode.StateProvider(stateProvider),
		)
		if err != nil {
			return fmt.Errorf("tendermint: failed to create node: %w", err)
		}
		if t.stateStore == nil {
			// Sanity check for the above wrapDbProvider hack in case the DB provider changes.
			return fmt.Errorf("tendermint: internal error: state database not set")
		}
		t.client = tmcli.New(t.node)
		t.failMonitor = newFailMonitor(t.ctx, t.Logger, t.node.ConsensusState().Wait)

		return nil
	}

	return nil
}

func (t *fullService) syncWorker() {
	checkSyncFn := func() (isSyncing bool, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("tendermint: node disappeared, terminated?")
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
				t.Logger.Info("Tendermint Node finished fast-sync")

				// Check latest block time.
				tmBlock, err := t.GetTendermintBlock(t.ctx, consensusAPI.HeightLatest)
				if err != nil {
					t.Logger.Error("Failed to get tendermint block",
						"err", err,
					)
					return
				}

				now := time.Now()
				// No committed blocks or latest block within threshold.
				if tmBlock == nil || now.Sub(tmBlock.Header.Time) < syncWorkerLastBlockTimeDiffThreshold {
					t.Logger.Info("Tendermint Node finished initial sync")
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
	sub, err := t.node.EventBus().SubscribeUnbuffered(t.ctx, tmSubscriberID, tmtypes.EventQueryNewBlock)
	if err != nil {
		t.Logger.Error("failed to subscribe to new block events",
			"err", err,
		)
		return
	}
	// Oh yes, this can actually return a nil subscription even though the error was also
	// nil if the node is just shutting down.
	if sub == (*tmpubsub.Subscription)(nil) {
		return
	}
	defer t.node.EventBus().Unsubscribe(t.ctx, tmSubscriberID, tmtypes.EventQueryNewBlock) // nolint: errcheck

	for {
		select {
		// Should not return on t.ctx.Done()/t.node.Quit() as that could lead to a deadlock.
		case <-sub.Cancelled():
			return
		case v := <-sub.Out():
			ev := v.Data().(tmtypes.EventDataNewBlock)
			t.blockNotifier.Broadcast(ev.Block)
		}
	}
}

// metrics updates oasis_consensus metrics by checking last accepted block info.
func (t *fullService) metrics() {
	ch, sub, err := t.WatchTendermintBlocks()
	if err != nil {
		t.Logger.Error("failed to watch tendermint blocks",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Tendermint uses specific public key encoding.
	pubKey := t.identity.ConsensusSigner.Public()
	myAddr := []byte(crypto.PublicKeyToTendermint(&pubKey).Address())
	for {
		var blk *tmtypes.Block
		select {
		case <-t.node.Quit():
			return
		case blk = <-ch:
		}

		// Was block proposed by our node.
		if bytes.Equal(myAddr, blk.ProposerAddress) {
			metrics.ProposedBlocks.With(labelTendermint).Inc()
		}

		// Was block voted for by our node. Ignore if there was no previous block.
		if blk.LastCommit != nil {
			for _, sig := range blk.LastCommit.Signatures {
				if sig.Absent() || sig.BlockIDFlag == tmtypes.BlockIDFlagNil {
					// Vote is missing, ignore.
					continue
				}

				if bytes.Equal(myAddr, sig.ValidatorAddress) {
					metrics.SignedBlocks.With(labelTendermint).Inc()
					break
				}
			}
		}
	}
}

// New creates a new Tendermint consensus backend.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	upgrader upgradeAPI.Backend,
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	// Retrieve the genesis document early so that it is possible to
	// use it while initializing other things.
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to get genesis doc: %w", err)
	}

	// Make sure that the consensus backend specified in the genesis
	// document is the correct one.
	if genesisDoc.Consensus.Backend != api.BackendName {
		return nil, fmt.Errorf("tendermint: genesis document contains incorrect consensus backend: %s",
			genesisDoc.Consensus.Backend,
		)
	}

	t := &fullService{
		commonNode: commonNode{
			BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
			ctx:                   ctx,
			identity:              identity,
			rpcCtx:                &tmrpctypes.Context{},
			genesis:               genesisDoc,
			dataDir:               dataDir,
			svcMgr:                cmbackground.NewServiceManager(logging.GetLogger("tendermint/servicemanager")),
			startedCh:             make(chan struct{}),
		},
		upgrader:        upgrader,
		blockNotifier:   pubsub.NewBroker(false),
		genesisProvider: genesisProvider,
		startedCh:       make(chan struct{}),
		syncedCh:        make(chan struct{}),
		quitCh:          make(chan struct{}),
	}

	t.Logger.Info("starting a full consensus node")

	// Create the submission manager.
	pd, err := consensusAPI.NewStaticPriceDiscovery(viper.GetUint64(tmcommon.CfgSubmissionGasPrice))
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to create submission manager: %w", err)
	}
	t.submissionMgr = consensusAPI.NewSubmissionManager(t, pd, viper.GetUint64(tmcommon.CfgSubmissionMaxFee))

	if err := t.lazyInit(); err != nil {
		return nil, fmt.Errorf("lazy init: %w", err)
	}

	return t, t.initialize()
}

func init() {
	Flags.String(cfgCoreExternalAddress, "", "tendermint address advertised to other nodes")
	Flags.String(CfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
	Flags.Uint64(CfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")
	Flags.StringSlice(CfgSentryUpstreamAddress, []string{}, "Tendermint nodes for which we act as sentry of the form ID@ip:port")
	Flags.StringSlice(CfgP2PPersistentPeer, []string{}, "Tendermint persistent peer(s) of the form ID@ip:port")
	Flags.StringSlice(CfgP2PUnconditionalPeerIDs, []string{}, "Tendermint unconditional peer IDs")
	Flags.Bool(CfgP2PDisablePeerExchange, false, "Disable Tendermint's peer-exchange reactor")
	Flags.Duration(CfgP2PPersistenPeersMaxDialPeriod, 0*time.Second, "Tendermint max timeout when redialing a persistent peer (default: unlimited)")
	Flags.Int(CfgP2PMaxNumInboundPeers, 40, "Max number of inbound peers")
	Flags.Int(CfgP2PMaxNumOutboundPeers, 20, "Max number of outbound peers (excluding persistent peers)")
	Flags.Int64(CfgP2PSendRate, 5120000, "Rate at which packets can be sent (bytes/sec)")
	Flags.Int64(CfgP2PRecvRate, 5120000, "Rate at which packets can be received (bytes/sec)")
	Flags.StringSlice(CfgP2PSeed, []string{}, "Tendermint seed node(s) of the form ID@host:port")
	Flags.Bool(CfgDebugP2PAllowDuplicateIP, false, "Allow multiple connections from the same IP")
	Flags.Uint64(CfgMinGasPrice, 0, "minimum gas price")
	Flags.Bool(CfgDebugDisableCheckTx, false, "do not perform CheckTx on incoming transactions (UNSAFE)")
	Flags.Bool(CfgDebugUnsafeReplayRecoverCorruptedWAL, false, "Enable automatic recovery from corrupted WAL during replay (UNSAFE).")

	Flags.Bool(CfgSupplementarySanityEnabled, false, "enable supplementary sanity checks (slows down consensus)")
	Flags.Uint64(CfgSupplementarySanityInterval, 10, "supplementary sanity check interval (in blocks)")

	// State sync.
	Flags.Bool(CfgConsensusStateSyncEnabled, false, "enable state sync")
	Flags.StringSlice(CfgConsensusStateSyncConsensusNode, []string{}, "state sync: consensus node to use for syncing the light client")
	Flags.Duration(CfgConsensusStateSyncTrustPeriod, 24*time.Hour, "state sync: light client trust period")
	Flags.Uint64(CfgConsensusStateSyncTrustHeight, 0, "state sync: light client trusted height")
	Flags.String(CfgConsensusStateSyncTrustHash, "", "state sync: light client trusted consensus header hash")

	_ = Flags.MarkHidden(CfgDebugP2PAllowDuplicateIP)
	_ = Flags.MarkHidden(CfgDebugDisableCheckTx)
	_ = Flags.MarkHidden(CfgDebugUnsafeReplayRecoverCorruptedWAL)

	_ = Flags.MarkHidden(CfgSupplementarySanityEnabled)
	_ = Flags.MarkHidden(CfgSupplementarySanityInterval)

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(db.Flags)
}
