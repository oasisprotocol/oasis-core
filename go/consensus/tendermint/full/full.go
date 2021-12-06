// Package full implements a full Tendermint consensus node.
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

	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	tmabciclient "github.com/tendermint/tendermint/abci/client"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmnode "github.com/tendermint/tendermint/node"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmcli "github.com/tendermint/tendermint/rpc/client/local"
	tmtypes "github.com/tendermint/tendermint/types"
	tminternal "github.com/tendermint/tendermint/uninternal"
	tmdb "github.com/tendermint/tm-db"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/random"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/metrics"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmflags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// CfgABCIPruneStrategy configures the ABCI state pruning strategy.
	CfgABCIPruneStrategy = "consensus.tendermint.abci.prune.strategy"
	// CfgABCIPruneNumKept configures the amount of kept heights if pruning is enabled.
	CfgABCIPruneNumKept = "consensus.tendermint.abci.prune.num_kept"
	// CfgABCIPruneInterval configures the ABCI state pruning interval.
	CfgABCIPruneInterval = "consensus.tendermint.abci.prune.interval"

	// CfgCheckpointerDisabled disables the ABCI state checkpointer.
	CfgCheckpointerDisabled = "consensus.tendermint.checkpointer.disabled"
	// CfgCheckpointerCheckInterval configures the ABCI state checkpointing check interval.
	CfgCheckpointerCheckInterval = "consensus.tendermint.checkpointer.check_interval"

	// CfgSentryUpstreamAddress defines nodes for which we act as a sentry for.
	CfgSentryUpstreamAddress = "consensus.tendermint.sentry.upstream_address"

	// CfgP2PPersistentPeer configures tendermint's persistent peer(s).
	CfgP2PPersistentPeer = "consensus.tendermint.p2p.persistent_peer"
	// CfgP2PPersistenPeersMaxDialPeriod configures the tendermint's persistent peer max dial period.
	CfgP2PPersistenPeersMaxDialPeriod = "consensus.tendermint.p2p.persistent_peers_max_dial_period"
	// CfgP2PDisablePeerExchange disables tendermint's peer-exchange (Pex) reactor.
	CfgP2PDisablePeerExchange = "consensus.tendermint.p2p.disable_peer_exchange"
	// CfgP2PUnconditionalPeerIDs configures tendermint's unconditional peer(s).
	CfgP2PUnconditionalPeerIDs = "consensus.tendermint.p2p.unconditional_peer_ids"

	// CfgDebugUnsafeReplayRecoverCorruptedWAL enables the debug and unsafe
	// automatic corrupted WAL recovery during replay.
	CfgDebugUnsafeReplayRecoverCorruptedWAL = "consensus.tendermint.debug.unsafe_replay_recover_corrupted_wal"

	// CfgMinGasPrice configures the minimum gas price for this validator.
	CfgMinGasPrice = "consensus.tendermint.min_gas_price"

	// CfgSupplementarySanityEnabled is the supplementary sanity enabled flag.
	CfgSupplementarySanityEnabled = "consensus.tendermint.supplementarysanity.enabled"
	// CfgSupplementarySanityInterval configures the supplementary sanity check interval.
	CfgSupplementarySanityInterval = "consensus.tendermint.supplementarysanity.interval"

	// CfgConsensusStateSyncEnabled enabled consensus state sync.
	CfgConsensusStateSyncEnabled = "consensus.tendermint.state_sync.enabled"
	// CfgConsensusStateSyncTrustPeriod is the light client trust period.
	CfgConsensusStateSyncTrustPeriod = "consensus.tendermint.state_sync.trust_period"
	// CfgConsensusStateSyncTrustHeight is the known trusted height for the light client.
	CfgConsensusStateSyncTrustHeight = "consensus.tendermint.state_sync.trust_height"
	// CfgConsensusStateSyncTrustHash is the known trusted block header hash for the light client.
	CfgConsensusStateSyncTrustHash = "consensus.tendermint.state_sync.trust_hash"

	// CfgUpgradeStopDelay is the average amount of time to delay shutting down the node on upgrade.
	CfgUpgradeStopDelay = "consensus.tendermint.upgrade.stop_delay"

	// CfgHaltHeight is the block height at which the local node should be shutdown.
	CfgHaltHeight = "consensus.tendermint.halt_height"
)

const (
	// Time difference threshold used when considering if node is done with
	// initial syncing. If difference is greater than the specified threshold
	// the node is considered not yet synced.
	// NOTE: this is only used during the initial sync.
	syncWorkerLastBlockTimeDiffThreshold = 1 * time.Minute

	minUpgradeStopWaitPeriod = 5 * time.Second

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
	*commonNode

	upgrader      upgradeAPI.Backend
	node          *tmnode.NodeImpl
	blockNotifier *pubsub.Broker
	failMonitor   *failMonitor

	submissionMgr consensusAPI.SubmissionManager

	genesisProvider genesisAPI.Provider
	syncedCh        chan struct{}
	quitCh          chan struct{}

	startFn  func() error
	stopOnce sync.Once

	nextSubscriberID uint64
}

// Implements consensusAPI.Backend.
func (t *fullService) Start() error {
	if t.started() {
		return fmt.Errorf("tendermint: service already started")
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
			return fmt.Errorf("tendermint: failed to start service: %w", err)
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
func (t *fullService) Mode() consensusAPI.Mode {
	return consensusAPI.ModeFull
}

// Implements consensusAPI.Backend.
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
			return errors.FromCode(result.GetCodespace(), result.GetCode(), result.GetLog())
		}
		return nil
	case <-txSub.Canceled():
		return context.Canceled
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *fullService) broadcastTxRaw(data []byte) error {
	rsp, err := t.commonNode.client.BroadcastTxSync(t.ctx, tmtypes.Tx(data))

	switch err {
	case nil:
	case tmtypes.ErrTxInCache:
		// Transaction already in the mempool or was recently there.
		return consensusAPI.ErrDuplicateTx
	default:
		return fmt.Errorf("tendermint: failed to submit to local mempool: %w", err)
	}

	if rsp.Code != tmabcitypes.CodeTypeOK {
		return errors.FromCode(rsp.Codespace, rsp.Code, rsp.Log)
	}

	return nil
}

func (t *fullService) newSubscriberID() string {
	return fmt.Sprintf("%s/subscriber-%d", tmSubscriberID, atomic.AddUint64(&t.nextSubscriberID, 1))
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	var protoEv tmproto.Evidence
	if err := protoEv.Unmarshal(evidence.Meta); err != nil {
		return fmt.Errorf("tendermint: malformed evidence while unmarshalling: %w", err)
	}

	ev, err := tmtypes.EvidenceFromProto(&protoEv)
	if err != nil {
		return fmt.Errorf("tendermint: malformed evidence while converting: %w", err)
	}

	if _, err := t.commonNode.client.BroadcastEvidence(ctx, ev); err != nil {
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
		return t.node.EventBus().Unsubscribe(t.ctx, tmpubsub.UnsubscribeArgs{Subscriber: subscriber, Query: query})
	}

	return fmt.Errorf("tendermint: unsubscribe called with no backing service")
}

// Implements consensusAPI.Backend.
func (t *fullService) SubmissionManager() consensusAPI.SubmissionManager {
	return t.submissionMgr
}

// Implements consensusAPI.Backend.
func (t *fullService) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
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
	status.Mode = consensusAPI.ModeFull

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
		status.NodePeers = tmcommon.GetPeersFromRPCEnvironment(t.node.RPCEnvironment())

		// Check if the local node is in the validator set for the latest (uncommitted) block.
		valSetHeight := status.LatestHeight + 1
		if valSetHeight < status.GenesisHeight {
			valSetHeight = status.GenesisHeight
		}
		vals, err := t.stateStore.LoadValidators(valSetHeight)
		if err != nil {
			// Failed to load validator set.
			status.IsValidator = false
		} else {
			consensusPk := t.identity.ConsensusSigner.Public()
			consensusAddr := []byte(crypto.PublicKeyToTendermint(&consensusPk).Address())
			status.IsValidator = vals.HasAddress(consensusAddr)
		}
	}

	return status, nil
}

// Implements consensusAPI.Backend.
func (t *fullService) GetNextBlockState(ctx context.Context) (*consensusAPI.NextBlockState, error) {
	if !t.started() {
		return nil, fmt.Errorf("tendermint: not yet started")
	}

	rs := t.node.RPCEnvironment().ConsensusState.GetRoundState()
	nbs := &consensusAPI.NextBlockState{
		Height: rs.Height,

		NumValidators: uint64(rs.Validators.Size()),
		VotingPower:   uint64(rs.Validators.TotalVotingPower()),
	}

	for i, val := range rs.Validators.Validators {
		var vote consensusAPI.Vote
		valNode, err := t.Registry().GetNodeByConsensusAddress(ctx, &registryAPI.ConsensusAddressQuery{
			Height:  consensusAPI.HeightLatest,
			Address: val.Address,
		})
		if err == nil {
			vote.NodeID = valNode.ID
			vote.EntityID = valNode.EntityID
			vote.EntityAddress = stakingAPI.NewAddress(valNode.EntityID)
		}
		vote.VotingPower = uint64(val.VotingPower)

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

// Implements consensusAPI.Backend.
func (t *fullService) WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription, error) {
	typedCh := make(chan *tmtypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (t *fullService) lazyInit() error { // nolint: gocyclo
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
	pruneCfg.PruneInterval = viper.GetDuration(CfgABCIPruneInterval)
	const minPruneInterval = 1 * time.Second
	if pruneCfg.PruneInterval < minPruneInterval {
		pruneCfg.PruneInterval = minPruneInterval
	}

	appConfig := &abci.ApplicationConfig{
		DataDir:                   filepath.Join(t.dataDir, tmcommon.StateDir),
		StorageBackend:            db.GetBackendName(),
		Pruning:                   pruneCfg,
		HaltEpochHeight:           t.genesis.HaltEpoch,
		HaltBlockHeight:           viper.GetUint64(CfgHaltHeight),
		MinGasPrice:               viper.GetUint64(CfgMinGasPrice),
		OwnTxSigner:               t.identity.NodeSigner.Public(),
		DisableCheckpointer:       viper.GetBool(CfgCheckpointerDisabled),
		CheckpointerCheckInterval: viper.GetDuration(CfgCheckpointerCheckInterval),
		InitialHeight:             uint64(t.genesis.Height),
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
	if cmflags.ConsensusValidator() {
		tenderConfig.Mode = tmconfig.ModeValidator
	} else {
		tenderConfig.Mode = tmconfig.ModeFull
	}
	tenderConfig.Moniker = "oasis-node-" + t.identity.NodeSigner.Public().String()
	tenderConfig.Mempool.Version = tmconfig.MempoolV0
	timeoutCommit := t.genesis.Consensus.Parameters.TimeoutCommit
	emptyBlockInterval := t.genesis.Consensus.Parameters.EmptyBlockInterval
	tenderConfig.Consensus.TimeoutCommit = timeoutCommit
	tenderConfig.Consensus.SkipTimeoutCommit = t.genesis.Consensus.Parameters.SkipTimeoutCommit
	tenderConfig.Consensus.CreateEmptyBlocks = true
	tenderConfig.Consensus.CreateEmptyBlocksInterval = emptyBlockInterval
	tenderConfig.Instrumentation.Prometheus = true
	tenderConfig.Instrumentation.PrometheusListenAddr = ""
	tenderConfig.TxIndex.Indexer = []string{"null"}
	tenderConfig.P2P.ListenAddress = viper.GetString(tmcommon.CfgCoreListenAddress)
	tenderConfig.P2P.ExternalAddress = viper.GetString(tmcommon.CfgCoreExternalAddress)
	tenderConfig.P2P.PexReactor = !viper.GetBool(CfgP2PDisablePeerExchange)
	tenderConfig.P2P.MaxConnections = uint16(viper.GetUint(tmcommon.CfgP2PMaxConnections))
	tenderConfig.P2P.MaxOutgoingConnections = 0 // Unlimited.
	tenderConfig.P2P.MaxPeers = uint16(viper.GetUint(tmcommon.CfgP2PMaxPeers))
	tenderConfig.P2P.WhitelistedPeers = strings.ToLower(strings.Join(viper.GetStringSlice(tmcommon.CfgP2PWhitelistedPeers), ","))
	tenderConfig.P2P.BlacklistedPeerIPs = strings.ToLower(strings.Join(viper.GetStringSlice(tmcommon.CfgP2PBlacklistedPeerIPs), ","))
	tenderConfig.P2P.SendRate = viper.GetInt64(tmcommon.CfgP2PSendRate)
	tenderConfig.P2P.RecvRate = viper.GetInt64(tmcommon.CfgP2PRecvRate)
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
	// BootstrapPeers need to be lowercase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparison to validate public keys.
	// Since Seeds is expected to be in comma-delimited ID@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.BootstrapPeers = strings.ToLower(strings.Join(viper.GetStringSlice(tmcommon.CfgP2PSeed), ","))
	tenderConfig.P2P.AddrBookStrict = !(viper.GetBool(tmcommon.CfgDebugP2PAddrBookLenient) && cmflags.DebugDontBlameOasis())
	tenderConfig.P2P.AllowDuplicateIP = viper.GetBool(tmcommon.CfgDebugP2PAllowDuplicateIP) && cmflags.DebugDontBlameOasis()
	tenderConfig.RPC.ListenAddress = ""
	tenderConfig.RPC.MaxSubscriptionsPerClient = 10

	sentryPeers := viper.GetStringSlice(tmcommon.CfgP2PSentryPeers)
	numSentryPeers := len(sentryPeers)
	if numSentryPeers > 0 {
		// The sentry peers setting is a convenience setting that automatically
		// adds the sentry peers to whitelisted peers and sets max connections
		// and max peers to total number of whitelisted peers.
		numWhitelisted := len(viper.GetStringSlice(tmcommon.CfgP2PWhitelistedPeers))
		if numWhitelisted > 0 {
			tenderConfig.P2P.WhitelistedPeers = tenderConfig.P2P.WhitelistedPeers + ","
		}
		tenderConfig.P2P.WhitelistedPeers = tenderConfig.P2P.WhitelistedPeers + strings.ToLower(strings.Join(viper.GetStringSlice(tmcommon.CfgP2PSentryPeers), ","))
		tenderConfig.P2P.MaxConnections = uint16(numSentryPeers + numWhitelisted)
		tenderConfig.P2P.MaxPeers = uint16(numSentryPeers + numWhitelisted)
	}

	if tenderConfig.P2P.WhitelistedPeers != "" {
		t.Logger.Info("using peer whitelist", "whitelisted_peers", tenderConfig.P2P.WhitelistedPeers)
	}

	if tenderConfig.P2P.BlacklistedPeerIPs != "" {
		t.Logger.Info("using peer IP blacklist", "blacklisted_peer_ips", tenderConfig.P2P.BlacklistedPeerIPs)
	}

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

	// Always try to migrate the Tendermint DB.
	// Our Tendermint fork has a DB version key, so checking if the DB has been
	// upgraded already or not is really cheap (and this kind of automatic
	// migration is a much nicer experience for our users).
	if merr := migrateTendermintDB(t.ctx, t.Logger, tenderConfig, dbProvider); merr != nil {
		return merr
	}

	// HACK: Wrap the provider so we can extract the state database handle. This is required because
	// Tendermint does not expose a way to access the state database and we need it to bypass some
	// stupid things like pagination on the in-process "client".
	wrapDbProvider := func(dbCtx *tmconfig.DBContext) (tmdb.DB, error) {
		rawDB, derr := dbProvider(dbCtx)
		if derr != nil {
			return nil, derr
		}
		db := db.WithCloser(rawDB, t.dbCloser)

		switch dbCtx.ID {
		case "state":
			// Tendermint state database.
			t.stateStore = tminternal.NewStore(db)
		case "blockstore":
			// Tendermint blockstore database.
			t.blockStoreDB = db
		default:
		}

		return db, nil
	}

	// Configure state sync if enabled.
	if viper.GetBool(CfgConsensusStateSyncEnabled) {
		t.Logger.Info("state sync enabled")

		// Enable state sync in the configuration.
		tenderConfig.StateSync.Enable = true
		tenderConfig.StateSync.UseP2P = true
		tenderConfig.StateSync.TrustHash = viper.GetString(CfgConsensusStateSyncTrustHash)
		tenderConfig.StateSync.TrustHeight = int64(viper.GetUint64(CfgConsensusStateSyncTrustHeight))
		tenderConfig.StateSync.TrustPeriod = viper.GetDuration(CfgConsensusStateSyncTrustPeriod)
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

		tmpk := crypto.SignerToTendermint(t.identity.P2PSigner)
		t.node, err = tmnode.MakeNode(tenderConfig,
			tendermintPV,
			tmtypes.NodeKey{ID: tmtypes.NodeIDFromPubKey(tmpk.PubKey()), PrivKey: tmpk},
			tmabciclient.NewLocalCreator(t.mux.Mux()),
			tendermintGenesisProvider,
			wrapDbProvider,
			tmcommon.NewLogAdapter(!viper.GetBool(tmcommon.CfgLogDebug)),
		)
		if err != nil {
			return fmt.Errorf("tendermint: failed to create node: %w", err)
		}
		if t.stateStore == nil {
			// Sanity check for the above wrapDbProvider hack in case the DB provider changes.
			return fmt.Errorf("tendermint: internal error: state database not set")
		}
		t.commonNode.client, err = tmcli.New(t.node)
		if err != nil {
			return fmt.Errorf("tendermint: failed to create RPC client: %w", err)
		}
		t.failMonitor = newFailMonitor(t.ctx, t.Logger, t.node.RPCEnvironment().ConsensusState.Wait)

		// Register a halt hook that handles upgrades gracefully.
		t.RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch beaconAPI.EpochTime, err error) {
			if !errors.Is(err, upgradeAPI.ErrStopForUpgrade) {
				return
			}

			// Mark this as a clean shutdown and request the node to stop gracefully.
			t.failMonitor.markCleanShutdown()

			// Wait before stopping to give time for P2P messages to propagate. Sleep for at least
			// minUpgradeStopWaitPeriod or the configured commit timeout.
			t.Logger.Info("waiting a bit before stopping the node for upgrade")
			waitPeriod := minUpgradeStopWaitPeriod
			if tc := t.genesis.Consensus.Parameters.TimeoutCommit; tc > waitPeriod {
				waitPeriod = tc
			}
			time.Sleep(waitPeriod)

			go func() {
				// Sleep another period so there is some time between when consensus shuts down and
				// when all the other services start shutting down.
				//
				// Randomize the period so that not all nodes shut down at the same time.
				delay := random.GetRandomValueFromInterval(0.5, rand.Float64(), viper.GetDuration(CfgUpgradeStopDelay))
				time.Sleep(delay)

				t.Logger.Info("stopping the node for upgrade")
				t.Stop()

				// Close the quit channel early to force the node to stop. This is needed because
				// the Tendermint node will otherwise never quit.
				close(t.quitCh)
			}()
		})

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
				// Check latest block time.
				tmBlock, err := t.GetTendermintBlock(t.ctx, consensusAPI.HeightLatest)
				if err != nil {
					t.Logger.Error("Failed to get tendermint block",
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
	defer t.node.EventBus().Unsubscribe(t.ctx, tmpubsub.UnsubscribeArgs{Subscriber: tmSubscriberID, Query: tmtypes.EventQueryNewBlock}) // nolint: errcheck

	for {
		select {
		// Should not return on t.ctx.Done()/t.node.Quit() as that could lead to a deadlock.
		case <-sub.Canceled():
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
	commonNode, err := newCommonNode(ctx, dataDir, identity, genesisProvider)
	if err != nil {
		return nil, err
	}

	t := &fullService{
		commonNode:      commonNode,
		upgrader:        upgrader,
		blockNotifier:   pubsub.NewBroker(false),
		genesisProvider: genesisProvider,
		syncedCh:        make(chan struct{}),
		quitCh:          make(chan struct{}),
	}
	// Common node needs access to parent struct for initializing consensus services.
	t.commonNode.parentNode = t

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
	Flags.String(CfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
	Flags.Uint64(CfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")
	Flags.Duration(CfgABCIPruneInterval, 2*time.Minute, "ABCI state pruning interval")
	Flags.Bool(CfgCheckpointerDisabled, false, "Disable the ABCI state checkpointer")
	Flags.Duration(CfgCheckpointerCheckInterval, 1*time.Minute, "ABCI state checkpointer check interval")
	Flags.StringSlice(CfgSentryUpstreamAddress, []string{}, "Tendermint nodes for which we act as sentry of the form ID@ip:port")
	Flags.StringSlice(CfgP2PPersistentPeer, []string{}, "Tendermint persistent peer(s) of the form ID@ip:port")
	Flags.StringSlice(CfgP2PUnconditionalPeerIDs, []string{}, "Tendermint unconditional peer IDs")
	Flags.Bool(CfgP2PDisablePeerExchange, false, "Disable Tendermint's peer-exchange reactor")
	Flags.Duration(CfgP2PPersistenPeersMaxDialPeriod, 0*time.Second, "Tendermint max timeout when redialing a persistent peer (default: unlimited)")
	Flags.Uint64(CfgMinGasPrice, 0, "minimum gas price")
	Flags.Bool(CfgDebugUnsafeReplayRecoverCorruptedWAL, false, "Enable automatic recovery from corrupted WAL during replay (UNSAFE).")

	Flags.Bool(CfgSupplementarySanityEnabled, false, "enable supplementary sanity checks (slows down consensus)")
	Flags.Uint64(CfgSupplementarySanityInterval, 10, "supplementary sanity check interval (in blocks)")

	Flags.Uint64(CfgHaltHeight, 0, "height at which to force-shutdown the node (in blocks)")

	// State sync.
	Flags.Bool(CfgConsensusStateSyncEnabled, false, "enable state sync")
	Flags.Duration(CfgConsensusStateSyncTrustPeriod, 24*time.Hour, "state sync: light client trust period")
	Flags.Uint64(CfgConsensusStateSyncTrustHeight, 0, "state sync: light client trusted height")
	Flags.String(CfgConsensusStateSyncTrustHash, "", "state sync: light client trusted consensus header hash")

	Flags.Duration(CfgUpgradeStopDelay, 60*time.Second, "average amount of time to delay shutting down the node on upgrade")

	_ = Flags.MarkHidden(CfgDebugUnsafeReplayRecoverCorruptedWAL)

	_ = Flags.MarkHidden(CfgSupplementarySanityEnabled)
	_ = Flags.MarkHidden(CfgSupplementarySanityInterval)

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(db.Flags)
}
