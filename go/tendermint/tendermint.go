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

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	tmabci "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/crypto"
	"github.com/oasislabs/ekiden/go/tendermint/db"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	configDir = "config"

	// CfgCoreListenAddress configures the tendermint core network listen address.
	CfgCoreListenAddress   = "tendermint.core.listen_address"
	cfgCoreExternalAddress = "tendermint.core.external_address"

	// CfgConsensusTimeoutCommit configures the tendermint timeout commit.
	CfgConsensusTimeoutCommit      = "tendermint.consensus.timeout_commit"
	cfgConsensusSkipTimeoutCommit  = "tendermint.consensus.skip_timeout_commit"
	cfgConsensusEmptyBlockInterval = "tendermint.consensus.empty_block_interval"

	cfgABCIPruneStrategy = "tendermint.abci.prune.strategy"
	cfgABCIPruneNumKept  = "tendermint.abci.prune.num_kept"

	// CfgP@PSeeds configures the tendermint seed nodes.
	CfgP2PSeeds = "tendermint.seeds"
	// CfgP2PSeedMode enables the tendermint seed mode.
	CfgP2PSeedMode = "tendermint.seed_mode"

	cfgLogDebug = "tendermint.log.debug"

	// CfgDebugP2PAddrBookLenient configures allowing non-routable addresses.
	CfgDebugP2PAddrBookLenient = "tendermint.debug.addr_book_lenient"
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
	// ekiden node.

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
	mux           *abci.ApplicationServer
	node          *tmnode.Node
	client        tmcli.Client
	blockNotifier *pubsub.Broker
	failMonitor   *failMonitor

	genesis                  genesis.Provider
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
		return errors.New("tendermint: service already started")
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
			return errors.Wrap(err, "tendermint: failed to start service")
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

func (t *tendermintService) Stop() {
	if !t.initialized() || !t.started() {
		return
	}

	t.failMonitor.markCleanShutdown()
	if err := t.node.Stop(); err != nil {
		t.Logger.Error("Error on stopping node", err)
	}

	t.mux.Stop()
	t.node.Wait()
}

func (t *tendermintService) Started() <-chan struct{} {
	return t.startedCh
}

func (t *tendermintService) Synced() <-chan struct{} {
	return t.syncedCh
}

func (t *tendermintService) GetAddresses() ([]node.Address, error) {
	addrURI := viper.GetString(cfgCoreExternalAddress)
	if addrURI == "" {
		addrURI = viper.GetString(CfgCoreListenAddress)
	}
	if addrURI == "" {
		return nil, fmt.Errorf("tendermint: no external address configured")
	}

	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to parse external address URL")
	}

	if u.Scheme != "tcp" {
		return nil, fmt.Errorf("tendermint: external address has invalid scheme: '%v'", u.Scheme)
	}

	// Handle the case when no IP is explicitly configured, and the
	// default value is used.
	if u.Hostname() == "0.0.0.0" {
		var port string
		if _, port, err = net.SplitHostPort(u.Host); err != nil {
			return nil, errors.Wrap(err, "tendermint: malformed external address host/port")
		}

		ip := common.GuessExternalAddress()
		if ip == nil {
			return nil, fmt.Errorf("tendermint: failed to guess external address")
		}

		u.Host = ip.String() + ":" + port
	}

	var addr node.Address
	if err = addr.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to parse external address host")
	}

	return []node.Address{addr}, nil
}

func (t *tendermintService) RegisterGenesisHook(hook func()) {
	if !t.initialized() {
		return
	}

	t.mux.RegisterGenesisHook(hook)
}

func (t *tendermintService) MarshalTx(tag byte, tx interface{}) tmtypes.Tx {
	message := cbor.Marshal(tx)
	return append([]byte{tag}, message...)
}

func (t *tendermintService) BroadcastTx(ctx context.Context, tag byte, tx interface{}, wait bool) error {
	return t.broadcastTx(ctx, tag, tx, wait)
}

func (t *tendermintService) broadcastTxRaw(data []byte) error {
	response, err := t.client.BroadcastTxSync(data)
	if err != nil {
		return errors.Wrap(err, "broadcast tx: commit failed")
	}

	if response.Code != api.CodeOK.ToInt() {
		return fmt.Errorf("broadcast tx: check tx failed: %d", response.Code)
	}

	return nil
}

func (t *tendermintService) newSubscriberID() string {
	return fmt.Sprintf("subscriber-%d", atomic.AddUint64(&t.nextSubscriberID, 1))
}

func (t *tendermintService) broadcastTx(ctx context.Context, tag byte, tx interface{}, wait bool) error {
	// Subscribe to the transaction being included in a block.
	data := t.MarshalTx(tag, tx)
	query := tmtypes.EventQueryTxFor(data)
	subID := t.newSubscriberID()
	txSub, err := t.Subscribe(subID, query)
	if err != nil {
		return err
	}
	if ptrSub, ok := txSub.(*tmpubsub.Subscription); ok && ptrSub == nil {
		t.Logger.Debug("broadcastTx: service has shut down. Cancel our context to recover")
		<-ctx.Done()
		return ctx.Err()
	}

	// This should be simple, but Tenermint's unbuffered pubsub is very dangerous
	// as if you don't drain the subscription channel, the whole pubsub system can
	// get blocked forever. So make sure to process events immediately.
	txCh := make(chan struct{})
	go func() {
		defer close(txCh)
		var seen bool
		for {
			select {
			case <-txSub.Out():
				if seen {
					// Discard any events past the first one.
					continue
				}
				txCh <- struct{}{}
				seen = true
			case <-txSub.Cancelled():
				return
			}
		}
	}()
	defer t.Unsubscribe(subID, query) // nolint: errcheck

	// First try to broadcast.
	if err := t.broadcastTxRaw(data); err != nil {
		return err
	}

	if !wait {
		return nil
	}

	// Wait for the transaction to be included in a block.
	select {
	case <-txCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *tendermintService) Query(path string, query interface{}, height int64) ([]byte, error) {
	var data []byte
	if query != nil {
		data = cbor.Marshal(query)
	}

	// We submit queries directly to our application instance as going through
	// tendermint's local client enforces a global mutex for all application
	// requests, blocking queries from within the application itself.
	//
	// This is safe to do as long as all application query handlers only access
	// state through the immutable tree.
	request := tmabci.RequestQuery{
		Data:   data,
		Path:   path,
		Height: height,
		Prove:  false,
	}
	response := t.mux.Mux().Query(request)

	if response.GetCode() != api.CodeOK.ToInt() {
		return nil, fmt.Errorf("query: failed (code=%s)", api.Code(response.GetCode()))
	}

	return response.GetValue(), nil
}

func (t *tendermintService) Subscribe(subscriber string, query tmpubsub.Query) (tmtypes.Subscription, error) {
	// Note: The tendermint documentation claims using SubscribeUnbuffered can
	// freeze the server, however, the buffered Subscribe can drop events, and
	// force-unsubscribe the channel if processing takes too long.

	subFn := func() (tmtypes.Subscription, error) {
		return t.node.EventBus().SubscribeUnbuffered(t.ctx, subscriber, query)
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

	return errors.New("tendermint: unsubscribe called with no backing service")
}

func (t *tendermintService) Pruner() abci.StatePruner {
	return t.mux.Pruner()
}

func (t *tendermintService) RegisterApplication(app abci.Application) error {
	if err := t.ForceInitialize(); err != nil {
		return err
	}
	if t.started() {
		return errors.New("tendermint: service already started")
	}

	return t.mux.Register(app)
}

func (t *tendermintService) ForceInitialize() error {
	t.Lock()
	defer t.Unlock()

	var err error
	if !t.isInitialized {
		t.Logger.Debug("Initializing tendermint local node.")
		err = t.lazyInit()
	}

	return err
}

func (t *tendermintService) GetBlock(height *int64) (*tmtypes.Block, error) {
	if t.client == nil {
		panic("client not available yet")
	}

	result, err := t.client.Block(height)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: block query failed")
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
		return nil, errors.Wrap(err, "tendermint: block results query failed")
	}

	return result, nil
}

func (t *tendermintService) WatchBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription) {
	typedCh := make(chan *tmtypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintService) NodeKey() *signature.PublicKey {
	pk := t.nodeSigner.Public()
	return &pk
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

	t.mux, err = abci.NewApplicationServer(t.ctx, t.dataDir, &pruneCfg)
	if err != nil {
		return err
	}

	// Tendermint needs the on-disk directories to be present when
	// launched like this, so create the relevant sub-directories
	// under the ekiden DataDir.
	tendermintDataDir := filepath.Join(t.dataDir, "tendermint")
	if err = initDataDir(tendermintDataDir); err != nil {
		return err
	}

	// Create Tendermint node.
	tenderConfig := tmconfig.DefaultConfig()
	_ = viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(tendermintDataDir)
	timeoutCommit := viper.GetDuration(CfgConsensusTimeoutCommit)
	emptyBlockInterval := viper.GetDuration(cfgConsensusEmptyBlockInterval)
	tenderConfig.Consensus.TimeoutCommit = timeoutCommit
	tenderConfig.Consensus.SkipTimeoutCommit = viper.GetBool(cfgConsensusSkipTimeoutCommit)
	tenderConfig.Consensus.CreateEmptyBlocks = true
	tenderConfig.Consensus.CreateEmptyBlocksInterval = emptyBlockInterval
	tenderConfig.Instrumentation.Prometheus = true
	tenderConfig.Instrumentation.PrometheusListenAddr = ""
	tenderConfig.TxIndex.Indexer = "null"
	tenderConfig.P2P.ListenAddress = viper.GetString(CfgCoreListenAddress)
	tenderConfig.P2P.ExternalAddress = viper.GetString(cfgCoreExternalAddress)
	tenderConfig.P2P.AllowDuplicateIP = true // HACK: e2e tests need this.
	tenderConfig.P2P.SeedMode = viper.GetBool(CfgP2PSeedMode)
	// Seed Ids need to be Lowecase as p2p/transport.go:MultiplexTransport.upgrade()
	// uses a case sensitive string comparision to validate public keys
	// Since Seeds is expected to be in comma-delimited id@host:port format,
	// lowercasing the whole string is ok.
	tenderConfig.P2P.Seeds = strings.ToLower(viper.GetString(CfgP2PSeeds))
	tenderConfig.P2P.AddrBookStrict = !viper.GetBool(CfgDebugP2PAddrBookLenient)
	tenderConfig.RPC.ListenAddress = ""

	tendermintPV, err := crypto.LoadOrGeneratePrivVal(tendermintDataDir, t.nodeSigner)
	if err != nil {
		return err
	}

	tmGenDoc, err := t.getGenesis(tenderConfig)
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
			// TODO/hsm: This needs to use a separte key.
			&tmp2p.NodeKey{PrivKey: crypto.UnsafeSignerToTendermint(t.nodeSigner)},
			tmproxy.NewLocalClientCreator(t.mux.Mux()),
			tendermintGenesisProvider,
			dbProvider,
			tmnode.DefaultMetricsProvider(tenderConfig.Instrumentation),
			newLogAdapter(!viper.GetBool(cfgLogDebug)),
		)
		if err != nil {
			return errors.Wrap(err, "tendermint: failed to create node")
		}
		t.client = tmcli.NewLocal(t.node)
		t.failMonitor = newFailMonitor(t.Logger, t.node.ConsensusState().Wait)

		return nil
	}

	t.isInitialized = true

	return nil
}

// genesisToTendermint converts the Ekiden genesis block to tendermint's format.
func genesisToTendermint(d *genesis.Document) (*tmtypes.GenesisDoc, error) {
	// WARNING: The AppState MUST be encoded as JSON since its type is
	// json.RawMessage which requires it to be valid JSON. It may appear
	// to work until you try to restore from an existing data directory.
	//
	// The runtime library sorts map keys, so the output of json.Marshal
	// should be deterministic.
	b, err := json.Marshal(d)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to serialize genesis doc")
	}
	doc := tmtypes.GenesisDoc{
		ChainID:         d.ChainID,
		GenesisTime:     d.Time,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
		AppState:        b,
	}

	var tmValidators []tmtypes.GenesisValidator
	for _, v := range d.Registry.Nodes {
		var openedNode node.Node
		if err := v.Open(registry.RegisterGenesisNodeSignatureContext, &openedNode); err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to verify validator")
		}
		// TODO: This should cross check that the entity is valid.
		if !openedNode.HasRoles(node.RoleValidator) {
			continue
		}

		pk := crypto.PublicKeyToTendermint(&openedNode.ID)
		validator := tmtypes.GenesisValidator{
			Address: pk.Address(),
			PubKey:  pk,
			Power:   api.VotingPower,
			Name:    "ekiden-validator-" + openedNode.ID.String(),
		}
		tmValidators = append(tmValidators, validator)
	}

	doc.Validators = tmValidators

	return &doc, nil
}

func (t *tendermintService) getGenesis(tenderConfig *tmconfig.Config) (*tmtypes.GenesisDoc, error) {
	doc, err := t.genesis.GetGenesisDocument()
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to get genesis doc")
	}

	var tmGenDoc *tmtypes.GenesisDoc
	if tmProvider, ok := t.genesis.(service.GenesisProvider); ok {
		// This is a single node config, because the genesis document was
		// missing, probably in unit tests.
		tmGenDoc, err = tmProvider.GetTendermintGenesisDocument()
	} else {
		tmGenDoc, err = genesisToTendermint(doc)
	}
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to create genesis doc")
	}

	// HACK: Certain test cases use TimeoutCommit < 1 sec, and care about the
	// BFT view of time pulling ahead.
	timeoutCommit := viper.GetDuration(CfgConsensusTimeoutCommit)
	tmGenDoc.ConsensusParams.Block.TimeIotaMs = int64(timeoutCommit / time.Millisecond)

	return tmGenDoc, nil
}

func (t *tendermintService) syncWorker() {
	checkSyncFn := func() (isSyncing bool, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("tendermint: node disappeared, terminated?")
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
func New(ctx context.Context, dataDir string, identity *identity.Identity, genesis genesis.Provider) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		blockNotifier:         pubsub.NewBroker(false),
		nodeSigner:            identity.NodeSigner,
		genesis:               genesis,
		ctx:                   ctx,
		dataDir:               dataDir,
		startedCh:             make(chan struct{}),
		syncedCh:              make(chan struct{}),
	}
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
	// Tendermint uses `module` like ekiden does, and to add insult to
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
	Flags.Duration(CfgConsensusTimeoutCommit, 1*time.Second, "tendermint commit timeout")
	Flags.Bool(cfgConsensusSkipTimeoutCommit, false, "skip tendermint commit timeout")
	Flags.Duration(cfgConsensusEmptyBlockInterval, 0*time.Second, "tendermint empty block interval")
	Flags.String(cfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
	Flags.Int64(cfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")
	Flags.Bool(CfgP2PSeedMode, false, "run the tendermint node in seed mode")
	Flags.String(CfgP2PSeeds, "", "comma-delimited id@host:port tendermint seed nodes")
	Flags.Bool(cfgLogDebug, false, "enable tendermint debug logs (very verbose)")
	Flags.Bool(CfgDebugP2PAddrBookLenient, false, "allow non-routable addresses")
	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(db.Flags)
}
