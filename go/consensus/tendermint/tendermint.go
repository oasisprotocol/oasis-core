package tendermint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	beaconAPI "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	cmservice "github.com/oasislabs/oasis-core/go/common/service"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	tmbeacon "github.com/oasislabs/oasis-core/go/consensus/tendermint/beacon"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/db"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/epochtime"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/epochtime_mock"
	tmkeymanager "github.com/oasislabs/oasis-core/go/consensus/tendermint/keymanager"
	tmregistry "github.com/oasislabs/oasis-core/go/consensus/tendermint/registry"
	tmroothash "github.com/oasislabs/oasis-core/go/consensus/tendermint/roothash"
	tmscheduler "github.com/oasislabs/oasis-core/go/consensus/tendermint/scheduler"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	tmstaking "github.com/oasislabs/oasis-core/go/consensus/tendermint/staking"
	epochtimeAPI "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesisAPI "github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/genesis/file"
	keymanagerAPI "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmbackground "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasislabs/oasis-core/go/registry"
	registryAPI "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash"
	roothashAPI "github.com/oasislabs/oasis-core/go/roothash/api"
	schedulerAPI "github.com/oasislabs/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	configDir = "config"

	// CfgCoreListenAddress configures the tendermint core network listen address.
	CfgCoreListenAddress   = "tendermint.core.listen_address"
	cfgCoreExternalAddress = "tendermint.core.external_address"

	cfgABCIPruneStrategy = "tendermint.abci.prune.strategy"
	cfgABCIPruneNumKept  = "tendermint.abci.prune.num_kept"

	// CfgP2PPrivatePeerID configures tendermint's private peer ID(s).
	CfgP2PPrivatePeerID = "tendermint.private_peer_id"
	// CfgP2PPersistentPeer configures tendermint's persistent peer(s).
	CfgP2PPersistentPeer = "tendermint.persistent_peer"
	// CfgP2PDisablePeerExchange disables tendermint's peer-exchange (Pex) reactor.
	CfgP2PDisablePeerExchange = "tendermint.disable_peer_exchange"
	// CfgP2PSeeds configures tendermint's seed node(s).
	CfgP2PSeed = "tendermint.seed"
	// CfgP2PSeedMode enables the tendermint seed mode.
	CfgP2PSeedMode = "tendermint.seed_mode"

	cfgLogDebug = "tendermint.log.debug"

	// CfgDebugP2PAddrBookLenient configures allowing non-routable addresses.
	CfgDebugP2PAddrBookLenient = "tendermint.debug.addr_book_lenient"

	// CfgConsensusMinGasPrice configures the minimum gas price for this validator.
	CfgConsensusMinGasPrice = "consensus.tendermint.min_gas_price"
)

var (
	_ service.TendermintService = (*tendermintService)(nil)

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

type failMonitor struct {
	sync.Mutex

	isCleanShutdown bool
}

func (m *failMonitor) markCleanShutdown() {
	m.Lock()
	defer m.Unlock()

	m.isCleanShutdown = true
}

func newFailMonitor(logger *logging.Logger, fn func()) *failMonitor {
	// Tendermint in it's infinite wisdom, doesn't terminate when
	// consensus fails, instead opting to "just" log, and tear down
	// the ConsensusState.  Since this behavior is stupid, watch for
	// unexpected ConsensusState termination, and panic to kill the
	// Oasis node.

	var m failMonitor
	go func() {
		// Wait(), basically.
		fn()

		// Check to see if the termination was expected or not.
		m.Lock()
		defer m.Unlock()

		if !m.isCleanShutdown {
			logger.Error("unexpected termination detected")
			panic("tendermint: unexpected termination detected, consensus failure?")
		}
	}()

	return &m
}

// IsSeed retuns true iff the node is configured as a seed node.
func IsSeed() bool {
	return viper.GetBool(CfgP2PSeedMode)
}

type tendermintService struct {
	sync.Mutex

	cmservice.BaseBackgroundService

	ctx           context.Context
	svcMgr        *cmbackground.ServiceManager
	mux           *abci.ApplicationServer
	node          *tmnode.Node
	client        tmcli.Client
	blockNotifier *pubsub.Broker
	failMonitor   *failMonitor

	beacon          beaconAPI.Backend
	epochtime       epochtimeAPI.Backend
	keymanager      keymanagerAPI.Backend
	registry        registryAPI.Backend
	registryMetrics *registry.MetricsUpdater
	roothash        roothashAPI.Backend
	staking         stakingAPI.Backend
	scheduler       schedulerAPI.Backend
	submissionMgr   consensusAPI.SubmissionManager

	genesis                  *genesisAPI.Document
	genesisProvider          genesisAPI.Provider
	consensusSigner          signature.Signer
	nodeSigner               signature.Signer
	dataDir                  string
	isInitialized, isStarted bool
	startedCh                chan struct{}
	syncedCh                 chan struct{}

	startFn func() error

	nextSubscriberID uint64
}

func (t *tendermintService) initialized() bool {
	t.Lock()
	defer t.Unlock()

	return t.isInitialized
}

func (t *tendermintService) started() bool {
	t.Lock()
	defer t.Unlock()

	return t.isStarted
}

func (t *tendermintService) Start() error {
	if t.started() {
		return fmt.Errorf("tendermint: service already started")
	}

	switch t.initialized() {
	case true:
		if err := t.mux.Start(); err != nil {
			return err
		}
		if err := t.startFn(); err != nil {
			return err
		}
		if err := t.node.Start(); err != nil {
			return fmt.Errorf("tendermint: failed to start service: %w", err)
		}
		go t.syncWorker()
		go t.worker()
	case false:
		close(t.syncedCh)
	}

	t.Lock()
	t.isStarted = true
	t.Unlock()

	close(t.startedCh)

	return nil
}

func (t *tendermintService) Quit() <-chan struct{} {
	if !t.started() {
		return make(chan struct{})
	}

	return t.node.Quit()
}

func (t *tendermintService) Cleanup() {
	t.svcMgr.Cleanup()
}

func (t *tendermintService) Stop() {
	if !t.initialized() || !t.started() {
		return
	}

	t.failMonitor.markCleanShutdown()
	if err := t.node.Stop(); err != nil {
		t.Logger.Error("Error on stopping node", err)
	}

	t.svcMgr.Stop()
	t.mux.Stop()
	t.node.Wait()
}

func (t *tendermintService) Started() <-chan struct{} {
	return t.startedCh
}

func (t *tendermintService) Synced() <-chan struct{} {
	return t.syncedCh
}

func (t *tendermintService) GetAddresses() ([]node.ConsensusAddress, error) {
	addrURI := viper.GetString(cfgCoreExternalAddress)
	if addrURI == "" {
		addrURI = viper.GetString(CfgCoreListenAddress)
	}
	if addrURI == "" {
		return nil, fmt.Errorf("tendermint: no external address configured")
	}

	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address URL: %w", err)
	}

	if u.Scheme != "tcp" {
		return nil, fmt.Errorf("tendermint: external address has invalid scheme: '%v'", u.Scheme)
	}

	// Handle the case when no IP is explicitly configured, and the
	// default value is used.
	if u.Hostname() == "0.0.0.0" {
		var port string
		if _, port, err = net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("tendermint: malformed external address host/port: %w", err)
		}

		ip := common.GuessExternalAddress()
		if ip == nil {
			return nil, fmt.Errorf("tendermint: failed to guess external address")
		}

		u.Host = ip.String() + ":" + port
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address host: %w", err)
	}
	addr.ID = t.nodeSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

func (t *tendermintService) ToGenesis(ctx context.Context, blockHeight int64) (*genesisAPI.Document, error) {
	logger := logging.GetLogger("tendermint/genesis")

	if blockHeight <= 0 {
		var err error
		if blockHeight, err = t.GetHeight(); err != nil {
			logger.Error("failed querying height",
				"err", err,
				"height", blockHeight,
			)
			return nil, err
		}
	}

	blk, err := t.GetBlock(&blockHeight)
	if err != nil {
		logger.Error("failed to get tendermint block",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	// Get initial genesis doc.
	genesisFileProvider, err := file.DefaultFileProvider()
	if err != nil {
		logger.Error("failed getting genesis file provider",
			"err", err,
		)
		return nil, err
	}
	genesisDoc, err := genesisFileProvider.GetGenesisDocument()
	if err != nil {
		logger.Error("failed getting genesis document from file provider",
			"err", err,
		)
		return nil, err
	}

	// Call ToGenesis on all backends and merge the results together.
	epochtimeGenesis, err := t.epochtime.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("epochtime ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	registryGenesis, err := t.registry.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("registry ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	roothashGenesis, err := t.roothash.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("roothash ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	stakingGenesis, err := t.staking.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("staking ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	keymanagerGenesis, err := t.keymanager.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("keymanager ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	schedulerGenesis, err := t.scheduler.ToGenesis(ctx, blockHeight)
	if err != nil {
		logger.Error("scheduler ToGenesis failure",
			"err", err,
			"block_height", blockHeight,
		)
		return nil, err
	}

	return &genesisAPI.Document{
		// XXX: Tendermint doesn't support restoring from non-0 height.
		// https://github.com/tendermint/tendermint/issues/2543
		Height:     blockHeight,
		ChainID:    genesisDoc.ChainID,
		HaltEpoch:  genesisDoc.HaltEpoch,
		Time:       blk.Header.Time,
		EpochTime:  *epochtimeGenesis,
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		KeyManager: *keymanagerGenesis,
		Scheduler:  *schedulerGenesis,
		Beacon:     genesisDoc.Beacon,
		Consensus:  genesisDoc.Consensus,
	}, nil
}

func (t *tendermintService) RegisterGenesisHook(hook func()) {
	if !t.initialized() {
		return
	}

	t.mux.RegisterGenesisHook(hook)
}

func (t *tendermintService) RegisterHaltHook(hook func(context.Context, int64, epochtimeAPI.EpochTime)) {
	if !t.initialized() {
		return
	}

	t.mux.RegisterHaltHook(hook)
}

func (t *tendermintService) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	// Subscribe to the transaction being included in a block.
	data := cbor.Marshal(tx)
	query := tmtypes.EventQueryTxFor(data)
	subID := t.newSubscriberID()
	txSub, err := t.Subscribe(subID, query)
	if err != nil {
		return err
	}
	if ptrSub, ok := txSub.(*tendermintPubsubBuffer).tmSubscription.(*tmpubsub.Subscription); ok && ptrSub == nil {
		t.Logger.Debug("broadcastTx: service has shut down. Cancel our context to recover")
		<-ctx.Done()
		return ctx.Err()
	}

	defer t.Unsubscribe(subID, query) // nolint: errcheck

	// Subscribe to the transaction becoming invalid.
	var txHash hash.Hash
	txHash.FromBytes(data)

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

func (t *tendermintService) broadcastTxRaw(data []byte) error {
	// We could use t.client.BroadcastTxSync but that is annoying as it
	// doesn't give you the right fields when CheckTx fails.
	mp := t.node.Mempool()

	// Submit the transaction to mempool and wait for response.
	ch := make(chan *tmabcitypes.Response, 1)
	err := mp.CheckTx(tmtypes.Tx(data), func(rsp *tmabcitypes.Response) {
		ch <- rsp
		close(ch)
	})
	if err != nil {
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

func (t *tendermintService) newSubscriberID() string {
	return fmt.Sprintf("subscriber-%d", atomic.AddUint64(&t.nextSubscriberID, 1))
}

func (t *tendermintService) SubmitEvidence(ctx context.Context, evidence consensusAPI.Evidence) error {
	if evidence.Kind() != consensusAPI.EvidenceKindConsensus {
		return fmt.Errorf("tendermint: unsupported evidence kind")
	}

	tmEvidence, ok := evidence.Unwrap().(tmtypes.Evidence)
	if !ok {
		return fmt.Errorf("tendermint: expected tendermint evidence, got something else")
	}

	if _, err := t.client.BroadcastEvidence(tmEvidence); err != nil {
		return fmt.Errorf("tendermint: broadcast evidence failed: %w", err)
	}

	return nil
}

func (t *tendermintService) Subscribe(subscriber string, query tmpubsub.Query) (tmtypes.Subscription, error) {
	// Note: The tendermint documentation claims using SubscribeUnbuffered can
	// freeze the server, however, the buffered Subscribe can drop events, and
	// force-unsubscribe the channel if processing takes too long.

	subFn := func() (tmtypes.Subscription, error) {
		sub, err := t.node.EventBus().SubscribeUnbuffered(t.ctx, subscriber, query)
		if err != nil {
			return nil, err
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

func (t *tendermintService) Unsubscribe(subscriber string, query tmpubsub.Query) error {
	if t.started() {
		return t.node.EventBus().Unsubscribe(t.ctx, subscriber, query)
	}

	return fmt.Errorf("tendermint: unsubscribe called with no backing service")
}

func (t *tendermintService) Pruner() abci.StatePruner {
	return t.mux.Pruner()
}

func (t *tendermintService) RegisterApplication(app abci.Application) error {
	return t.mux.Register(app)
}

func (t *tendermintService) SetTransactionAuthHandler(handler abci.TransactionAuthHandler) error {
	return t.mux.SetTransactionAuthHandler(handler)
}

func (t *tendermintService) GetGenesis() *genesisAPI.Document {
	return t.genesis
}

func (t *tendermintService) TransactionAuthHandler() consensusAPI.TransactionAuthHandler {
	return t.mux.TransactionAuthHandler()
}

func (t *tendermintService) SubmissionManager() consensusAPI.SubmissionManager {
	return t.submissionMgr
}

func (t *tendermintService) EpochTime() epochtimeAPI.Backend {
	return t.epochtime
}

func (t *tendermintService) Beacon() beaconAPI.Backend {
	return t.beacon
}

func (t *tendermintService) KeyManager() keymanagerAPI.Backend {
	return t.keymanager
}

func (t *tendermintService) Registry() registryAPI.Backend {
	return t.registry
}

func (t *tendermintService) RootHash() roothashAPI.Backend {
	return t.roothash
}

func (t *tendermintService) Staking() stakingAPI.Backend {
	return t.staking
}

func (t *tendermintService) Scheduler() schedulerAPI.Backend {
	return t.scheduler
}

func (t *tendermintService) initialize() error {
	t.Lock()
	defer t.Unlock()

	if t.isInitialized {
		return nil
	}

	if err := t.lazyInit(); err != nil {
		return err
	}

	if err := t.initEpochtime(); err != nil {
		return err
	}
	if err := t.mux.SetEpochtime(t.epochtime); err != nil {
		return err
	}

	// Initialize the rest of backends.
	var err error
	if t.beacon, err = tmbeacon.New(t.ctx, t); err != nil {
		t.Logger.Error("initialize: failed to initialize beacon backend",
			"err", err,
		)
		return err
	}

	if t.keymanager, err = tmkeymanager.New(t.ctx, t); err != nil {
		t.Logger.Error("initialize: failed to initialize keymanager backend",
			"err", err,
		)
		return err
	}

	if t.registry, err = tmregistry.New(t.ctx, t); err != nil {
		t.Logger.Error("initialize: failed to initialize registry backend",
			"err", err,
		)
		return err
	}
	t.registryMetrics = registry.NewMetricsUpdater(t.ctx, t.registry)
	t.svcMgr.RegisterCleanupOnly(t.registry, "registry backend")
	t.svcMgr.RegisterCleanupOnly(t.registryMetrics, "registry metrics updater")

	if t.staking, err = tmstaking.New(t.ctx, t); err != nil {
		t.Logger.Error("staking: failed to initialize staking backend",
			"err", err,
		)
		return err
	}
	t.svcMgr.RegisterCleanupOnly(t.staking, "staking backend")

	if t.scheduler, err = tmscheduler.New(t.ctx, t); err != nil {
		t.Logger.Error("scheduler: failed to initialize scheduler backend",
			"err", err,
		)
		return err
	}
	t.svcMgr.RegisterCleanupOnly(t.scheduler, "scheduler backend")

	if t.roothash, err = tmroothash.New(t.ctx, t.dataDir, t.beacon, t); err != nil {
		t.Logger.Error("roothash: failed to initialize roothash backend",
			"err", err,
		)
		return err
	}
	t.roothash = roothash.NewMetricsWrapper(t.roothash)
	t.svcMgr.RegisterCleanupOnly(t.roothash, "roothash backend")

	return nil
}

func (t *tendermintService) GetBlock(height *int64) (*tmtypes.Block, error) {
	if t.client == nil {
		panic("client not available yet")
	}

	result, err := t.client.Block(height)
	if err != nil {
		return nil, fmt.Errorf("tendermint: block query failed: %w", err)
	}

	return result.Block, nil
}

func (t *tendermintService) GetHeight() (int64, error) {
	blk, err := t.GetBlock(nil)
	if err != nil {
		return 0, err
	}

	return blk.Header.Height, nil
}

func (t *tendermintService) GetBlockResults(height *int64) (*tmrpctypes.ResultBlockResults, error) {
	if t.client == nil {
		panic("client not available yet")
	}

	result, err := t.client.BlockResults(height)
	if err != nil {
		return nil, fmt.Errorf("tendermint: block results query failed: %w", err)
	}

	return result, nil
}

func (t *tendermintService) WatchBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription) {
	typedCh := make(chan *tmtypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintService) ConsensusKey() signature.PublicKey {
	return t.consensusSigner.Public()
}

func (t *tendermintService) initEpochtime() error {
	var epochTime epochtimeAPI.Backend
	var err error
	if t.genesis.EpochTime.Parameters.DebugMockBackend {
		epochTime, err = epochtimemock.New(t.ctx, t)
		if err != nil {
			t.Logger.Error("initEpochtime: failed to initialize mock epochtime backend",
				"err", err,
			)
			return err
		}
	} else {
		epochTime, err = epochtime.New(t.ctx, t, t.genesis.EpochTime.Parameters.Interval)
		if err != nil {
			t.Logger.Error("initEpochtime: failed to initialize epochtime backend",
				"err", err,
			)
			return err
		}
	}
	t.epochtime = epochTime
	return nil
}

func (t *tendermintService) lazyInit() error {
	if t.isInitialized {
		return nil
	}

	var err error

	// Create Tendermint application mux.
	var pruneCfg abci.PruneConfig
	pruneStrat := viper.GetString(cfgABCIPruneStrategy)
	if err = pruneCfg.Strategy.FromString(pruneStrat); err != nil {
		return err
	}
	pruneNumKept := int64(viper.GetInt(cfgABCIPruneNumKept))
	pruneCfg.NumKept = pruneNumKept

	appConfig := &abci.ApplicationConfig{
		DataDir:         t.dataDir,
		Pruning:         pruneCfg,
		HaltEpochHeight: t.genesis.HaltEpoch,
		MinGasPrice:     viper.GetUint64(CfgConsensusMinGasPrice),
	}
	t.mux, err = abci.NewApplicationServer(t.ctx, appConfig)
	if err != nil {
		return err
	}

	// Tendermint needs the on-disk directories to be present when
	// launched like this, so create the relevant sub-directories
	// under the node DataDir.
	tendermintDataDir := filepath.Join(t.dataDir, "tendermint")
	if err = initDataDir(tendermintDataDir); err != nil {
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
	tenderConfig.Instrumentation.Prometheus = true
	tenderConfig.Instrumentation.PrometheusListenAddr = ""
	tenderConfig.TxIndex.Indexer = "null"
	tenderConfig.P2P.ListenAddress = viper.GetString(CfgCoreListenAddress)
	tenderConfig.P2P.ExternalAddress = viper.GetString(cfgCoreExternalAddress)
	tenderConfig.P2P.AllowDuplicateIP = true // HACK: e2e tests need this.
	// Convert persistent peer IDs to lowercase (like other IDs) since
	// Tendermint stores them in a map and uses a case sensitive string
	// comparison to check ID equality.
	tenderConfig.P2P.PrivatePeerIDs = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PPrivatePeerID), ","))
	// Persistent peers need to be lowecase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparision to validate public keys.
	// Since persistent peers is expected to be in comma-delimited ID@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.PersistentPeers = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PPersistentPeer), ","))
	tenderConfig.P2P.PexReactor = !viper.GetBool(CfgP2PDisablePeerExchange)
	tenderConfig.P2P.SeedMode = viper.GetBool(CfgP2PSeedMode)
	// Seed Ids need to be Lowecase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparision to validate public keys.
	// Since Seeds is expected to be in comma-delimited ID@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.Seeds = strings.ToLower(strings.Join(viper.GetStringSlice(CfgP2PSeed), ","))
	tenderConfig.P2P.AddrBookStrict = !viper.GetBool(CfgDebugP2PAddrBookLenient)
	tenderConfig.RPC.ListenAddress = ""

	if !tenderConfig.P2P.PexReactor {
		t.Logger.Info("pex reactor disabled",
			logging.LogEvent, api.LogEventPeerExchangeDisabled,
		)
	}

	tendermintPV, err := crypto.LoadOrGeneratePrivVal(tendermintDataDir, t.consensusSigner)
	if err != nil {
		return err
	}

	tmGenDoc, err := t.getTendermintGenesis()
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

	unsafeNodeSigner, ok := t.nodeSigner.(signature.UnsafeSigner)
	if !ok {
		t.Logger.Error("node signer does not allow private key access")
		return fmt.Errorf("tendermint: node signer does not allow private key access")
	}

	// HACK: tmnode.NewNode() triggers block replay and or ABCI chain
	// initialization, instead of t.node.Start().  This is a problem
	// because at the time that lazyInit() is called, none of the ABCI
	// applications are registered.
	//
	// Defer actually initializing the node till after everything
	// else is setup.
	t.startFn = func() error {
		t.node, err = tmnode.NewNode(tenderConfig,
			tendermintPV,
			// TODO/hsm: This needs to use a separate key or something.
			&tmp2p.NodeKey{PrivKey: crypto.UnsafeSignerToTendermint(unsafeNodeSigner)},
			tmproxy.NewLocalClientCreator(t.mux.Mux()),
			tendermintGenesisProvider,
			dbProvider,
			tmnode.DefaultMetricsProvider(tenderConfig.Instrumentation),
			newLogAdapter(!viper.GetBool(cfgLogDebug)),
		)
		if err != nil {
			return fmt.Errorf("tendermint: failed to create node: %w", err)
		}
		t.client = tmcli.NewLocal(t.node)
		t.failMonitor = newFailMonitor(t.Logger, t.node.ConsensusState().Wait)

		return nil
	}

	t.isInitialized = true

	return nil
}

// genesisToTendermint converts the Oasis genesis block to Tendermint's format.
func genesisToTendermint(d *genesisAPI.Document) (*tmtypes.GenesisDoc, error) {
	// WARNING: The AppState MUST be encoded as JSON since its type is
	// json.RawMessage which requires it to be valid JSON. It may appear
	// to work until you try to restore from an existing data directory.
	//
	// The runtime library sorts map keys, so the output of json.Marshal
	// should be deterministic.
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to serialize genesis doc: %w", err)
	}

	// Translate special "disable block gas limit" value as Tendermint uses
	// -1 for some reason (as if a zero limit makes sense) and we use 0.
	maxBlockGas := int64(d.Consensus.Parameters.MaxBlockGas)
	if maxBlockGas == 0 {
		maxBlockGas = -1
	}

	doc := tmtypes.GenesisDoc{
		ChainID:     d.ChainID,
		GenesisTime: d.Time,
		ConsensusParams: &tmtypes.ConsensusParams{
			Block: tmtypes.BlockParams{
				MaxBytes:   int64(d.Consensus.Parameters.MaxBlockSize),
				MaxGas:     maxBlockGas,
				TimeIotaMs: 1000,
			},
			Evidence: tmtypes.EvidenceParams{
				MaxAge: int64(d.Consensus.Parameters.MaxEvidenceAge),
			},
			Validator: tmtypes.ValidatorParams{
				PubKeyTypes: []string{tmtypes.ABCIPubKeyTypeEd25519},
			},
		},
		AppState: b,
	}

	var tmValidators []tmtypes.GenesisValidator
	for _, v := range d.Registry.Nodes {
		var openedNode node.Node
		if err := v.Open(registryAPI.RegisterGenesisNodeSignatureContext, &openedNode); err != nil {
			return nil, fmt.Errorf("tendermint: failed to verify validator: %w", err)
		}
		// TODO: This should cross check that the entity is valid.
		if !openedNode.HasRoles(node.RoleValidator) {
			continue
		}

		pk := crypto.PublicKeyToTendermint(&openedNode.Consensus.ID)
		validator := tmtypes.GenesisValidator{
			Address: pk.Address(),
			PubKey:  pk,
			Power:   api.VotingPower,
			Name:    "oasis-validator-" + openedNode.ID.String(),
		}
		tmValidators = append(tmValidators, validator)
	}

	doc.Validators = tmValidators

	return &doc, nil
}

func (t *tendermintService) getTendermintGenesis() (*tmtypes.GenesisDoc, error) {
	var (
		tmGenDoc *tmtypes.GenesisDoc
		err      error
	)
	if tmProvider, ok := t.genesisProvider.(service.GenesisProvider); ok {
		// This is a single node config, because the genesis document was
		// missing, probably in unit tests.
		tmGenDoc, err = tmProvider.GetTendermintGenesisDocument()
	} else {
		tmGenDoc, err = genesisToTendermint(t.genesis)
	}
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to create genesis doc: %w", err)
	}

	// HACK: Certain test cases use TimeoutCommit < 1 sec, and care about the
	// BFT view of time pulling ahead.
	timeoutCommit := t.genesis.Consensus.Parameters.TimeoutCommit
	tmGenDoc.ConsensusParams.Block.TimeIotaMs = int64(timeoutCommit / time.Millisecond)

	return tmGenDoc, nil
}

func (t *tendermintService) syncWorker() {
	checkSyncFn := func() (isSyncing bool, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("tendermint: node disappeared, terminated?")
			}
		}()

		return t.node.ConsensusReactor().FastSync(), nil
	}

	for {
		select {
		case <-t.node.Quit():
			return
		case <-time.After(1 * time.Second):
			isSyncing, err := checkSyncFn()
			if err != nil {
				t.Logger.Error("Failed to poll FastSync",
					"err", err,
				)
				return
			}
			if !isSyncing {
				t.Logger.Info("Tendermint Node finished fast-sync")
				close(t.syncedCh)
				return
			}
		}
	}
}

func (t *tendermintService) worker() {
	// Subscribe to other events here as needed, no need to spawn additional
	// workers.
	sub, err := t.Subscribe("tendermint/worker", tmtypes.EventQueryNewBlock)
	if err != nil {
		t.Logger.Error("worker: failed to subscribe to new block events",
			"err", err,
		)
		return
	}
	defer t.Unsubscribe("tendermint/worker", tmtypes.EventQueryNewBlock) // nolint:errcheck

	for {
		select {
		case <-t.node.Quit():
			return
		case <-sub.Cancelled():
			return
		case v := <-sub.Out():
			ev := v.Data().(tmtypes.EventDataNewBlock)
			t.blockNotifier.Broadcast(ev.Block)
		}
	}
}

// New creates a new Tendermint service.
func New(ctx context.Context, dataDir string, identity *identity.Identity, genesisProvider genesisAPI.Provider) (service.TendermintService, error) {
	// Retrive the genesis document early so that it is possible to
	// use it while initializing other things.
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to get genesis doc: %w", err)
	}

	// Sanity check genesis document.
	if err = genesisDoc.SanityCheck(); err != nil {
		return nil, err
	}

	t := &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		svcMgr:                cmbackground.NewServiceManager(logging.GetLogger("tendermint/servicemanager")),
		blockNotifier:         pubsub.NewBroker(false),
		consensusSigner:       identity.ConsensusSigner,
		nodeSigner:            identity.NodeSigner,
		genesis:               genesisDoc,
		genesisProvider:       genesisProvider,
		ctx:                   ctx,
		dataDir:               dataDir,
		startedCh:             make(chan struct{}),
		syncedCh:              make(chan struct{}),
	}

	// Create the submission manager.
	t.submissionMgr = consensusAPI.NewSubmissionManager(t)

	return t, t.initialize()
}

func initDataDir(dataDir string) error {
	subDirs := []string{
		configDir,
		"data", // Required by `tendermint/privval/FilePV.Save()`.
	}

	if err := common.Mkdir(dataDir); err != nil {
		return err
	}

	for _, subDir := range subDirs {
		if err := common.Mkdir(filepath.Join(dataDir, subDir)); err != nil {
			return err
		}
	}

	return nil
}

type logAdapter struct {
	*logging.Logger

	baseLogger    *logging.Logger
	suppressDebug bool

	keyVals []interface{}
}

func (a *logAdapter) With(keyvals ...interface{}) tmlog.Logger {
	// Tendermint uses `module` like oasis-node does, and to add insult to
	// injury will cave off child loggers with subsequence calls to
	// `With()`, resulting in multiple `module` keys.
	//
	// Do the right thing by:
	//  * Prefixing the `module` values with `tendermint:`
	//  * Coallece the multiple `module` values.
	//
	// This is more convoluted than it needs to be because the kit-log
	// prefix vector is private.

	findModule := func(vec []interface{}) (string, int) {
		for i, v := range vec {
			if i&1 != 0 {
				continue
			}

			k := v.(string)
			if k != "module" {
				continue
			}
			if i+1 > len(vec) {
				panic("With(): tendermint core logger, missing 'module' value")
			}

			vv := vec[i+1].(string)

			return vv, i + 1
		}
		return "", -1
	}

	parentMod, parentIdx := findModule(a.keyVals)

	childKeyVals := append([]interface{}{}, a.keyVals...)
	childMod, childIdx := findModule(keyvals)
	if childIdx < 0 {
		// "module" was not specified for this child, use the one belonging
		// to the parent.
		if parentIdx < 0 {
			// This should *NEVER* happen, if it does, it means that tendermint
			// called `With()` on the base logAdapter without setting a module.
			panic("With(): tendermint core logger, no sensible parent 'module'")
		}
		childKeyVals = append(childKeyVals, keyvals...)
	} else if parentIdx < 0 {
		// No parent logger, this must be a child of the base logAdapter.
		keyvals[childIdx] = "tendermint:" + childMod
		childKeyVals = append(childKeyVals, keyvals...)
	} else {
		// Append the child's module to the parent's.
		childKeyVals[parentIdx] = parentMod + "/" + childMod
		for i, v := range keyvals {
			// And omit the non-re=written key/value from the those passed to
			// the kit-log logger.
			if i != childIdx-1 && i != childIdx {
				childKeyVals = append(childKeyVals, v)
			}
		}
	}

	return &logAdapter{
		Logger:        a.baseLogger.With(childKeyVals...),
		baseLogger:    a.baseLogger,
		suppressDebug: a.suppressDebug,
		keyVals:       childKeyVals,
	}
}

func (a *logAdapter) Info(msg string, keyvals ...interface{}) {
	a.Logger.Info(msg, keyvals...)
}

func (a *logAdapter) Error(msg string, keyvals ...interface{}) {
	a.Logger.Error(msg, keyvals...)
}

func (a *logAdapter) Debug(msg string, keyvals ...interface{}) {
	if !a.suppressDebug {
		a.Logger.Debug(msg, keyvals...)
	}
}

func newLogAdapter(suppressDebug bool) tmlog.Logger {
	// Need an extra level of unwinding because the Debug wrapper
	// exists.
	//
	// This might be able to be replaced with the per-module log
	// level instead.
	return &logAdapter{
		Logger:        logging.GetLoggerEx("tendermint:base", 1),
		baseLogger:    logging.GetLoggerEx("", 1), // Tendermint sets the module, repeatedly.
		suppressDebug: suppressDebug,
	}
}

func init() {
	Flags.String(CfgCoreListenAddress, "tcp://0.0.0.0:26656", "tendermint core listen address")
	Flags.String(cfgCoreExternalAddress, "", "tendermint address advertised to other nodes")
	Flags.String(cfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
	Flags.Int64(cfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")
	Flags.StringSlice(CfgP2PPrivatePeerID, []string{}, "Tendermint private peer(s) (i.e. they will not be gossiped to other peers) of the form ID")
	Flags.StringSlice(CfgP2PPersistentPeer, []string{}, "Tendermint persistent peer(s) of the form ID@ip:port")
	Flags.Bool(CfgP2PDisablePeerExchange, false, "Disable Tendermint's peer-exchange reactor")
	Flags.Bool(CfgP2PSeedMode, false, "run the tendermint node in seed mode")
	Flags.StringSlice(CfgP2PSeed, []string{}, "Tendermint seed node(s) of the form ID@host:port")
	Flags.Bool(cfgLogDebug, false, "enable tendermint debug logs (very verbose)")
	Flags.Bool(CfgDebugP2PAddrBookLenient, false, "allow non-routable addresses")
	Flags.Uint64(CfgConsensusMinGasPrice, 0, "minimum gas price")

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(db.Flags)
	Flags.AddFlagSet(tmroothash.Flags)
}
