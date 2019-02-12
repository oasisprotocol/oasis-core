package tendermint

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	tmabci "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmpex "github.com/tendermint/tendermint/p2p/pex"
	tmpriv "github.com/tendermint/tendermint/privval"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/bootstrap"
	"github.com/oasislabs/ekiden/go/tendermint/db/bolt"
	"github.com/oasislabs/ekiden/go/tendermint/internal/crypto"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	configDir = "config"

	cfgCoreGenesisFile     = "tendermint.core.genesis_file"
	cfgCoreListenAddress   = "tendermint.core.listen_address"
	cfgCoreExternalAddress = "tendermint.core.external_address"

	cfgConsensusTimeoutCommit      = "tendermint.consensus.timeout_commit"
	cfgConsensusSkipTimeoutCommit  = "tendermint.consensus.skip_timeout_commit"
	cfgConsensusEmptyBlockInterval = "tendermint.consensus.empty_block_interval"

	cfgABCIPruneStrategy = "tendermint.abci.prune.strategy"
	cfgABCIPruneNumKept  = "tendermint.abci.prune.num_kept"

	cfgLogDebug = "tendermint.log.debug"

	cfgDebugBootstrapAddress       = "tendermint.debug.bootstrap.address"
	cfgDebugBootstrapNodeName      = "tendermint.debug.bootstrap.node_name"
	cfgDebugConsensusBlockTimeIota = "tendermint.debug.block_time_iota"
	cfgDebugP2PAddrBookLenient     = "tendermint.debug.addr_book_lenient"
)

var (
	_ service.TendermintService = (*tendermintService)(nil)
)

type tendermintService struct {
	sync.Mutex

	cmservice.BaseBackgroundService

	ctx           context.Context
	mux           *abci.ApplicationServer
	node          *tmnode.Node
	client        tmcli.Client
	blockNotifier *pubsub.Broker

	validatorKey             *signature.PrivateKey
	nodeKey                  *signature.PrivateKey
	dataDir                  string
	isInitialized, isStarted bool
	startedCh                chan struct{}

	startFn func() error
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
	if !t.initialized() {
		return nil
	}

	if err := t.mux.Start(); err != nil {
		return err
	}
	if err := t.startFn(); err != nil {
		return err
	}
	if err := t.node.Start(); err != nil {
		return errors.Wrap(err, "tendermint: failed to start service")
	}

	go t.worker()

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
	if !t.initialized() && !t.started() {
		return
	}

	if err := t.node.Stop(); err != nil {
		t.Logger.Error("Error on stopping node", err)
	}

	t.mux.Stop()
	t.node.Wait()
}

func (t *tendermintService) Started() <-chan struct{} {
	return t.startedCh
}

func (t *tendermintService) BroadcastTx(tag byte, tx interface{}) error {
	message := cbor.Marshal(tx)
	data := append([]byte{tag}, message...)

	response, err := t.client.BroadcastTxCommit(data)
	if err != nil {
		return errors.Wrap(err, "broadcast tx: commit failed")
	}

	if response.CheckTx.Code != api.CodeOK.ToInt() {
		return fmt.Errorf("broadcast tx: check tx failed: %s", response.CheckTx.Info)
	}
	if response.DeliverTx.Code != api.CodeOK.ToInt() {
		return fmt.Errorf("broadcast tx: deliver tx failed: %s", response.DeliverTx.Info)
	}

	return nil
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

func (t *tendermintService) Subscribe(ctx context.Context, subscriber string, query tmpubsub.Query, out chan<- interface{}) error {
	subFn := func() error {
		return t.node.EventBus().Subscribe(t.ctx, subscriber, query, out)
	}

	if t.started() {
		return subFn()
	}

	// The node doesn't exist until it's started since, creating the node
	// triggers replay, InitChain, and etc.
	go func() {
		<-t.startedCh
		if err := subFn(); err != nil {
			t.Logger.Error("failed defered Subscribe",
				"err", err,
				"subscriber", subscriber,
				"query", query,
			)
			panic("tendermint: defered Subscribe failure")
		}
	}()

	return nil
}

func (t *tendermintService) Unsubscribe(ctx context.Context, subscriber string, query tmpubsub.Query) error {
	if t.started() {
		return t.node.EventBus().Unsubscribe(t.ctx, subscriber, query)
	}

	return errors.New("tendermint: unsubscribe called with no backing service")
}

func (t *tendermintService) Genesis() (*tmrpctypes.ResultGenesis, error) {
	if t.client == nil {
		panic("client not available yet")
	}

	return t.client.Genesis()
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

func (t *tendermintService) GetBlock(height int64) (*tmtypes.Block, error) {
	if t.client == nil {
		panic("client not available yet")
	}

	result, err := t.client.Block(&height)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: block query failed")
	}

	return result.Block, nil
}

func (t *tendermintService) GetBlockResults(height int64) (*tmrpctypes.ResultBlockResults, error) {
	result, err := t.client.BlockResults(&height)
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
	// Should *never* happen unless this is called prior to any backends
	// being initialized.
	if t.nodeKey == nil {
		panic("node key not available yet")
	}

	pk := t.nodeKey.Public()

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

	// Initialize the node (P2P) key.
	if t.nodeKey, err = initNodeKey(tendermintDataDir); err != nil {
		return err
	}
	t.Logger.Debug("loaded/generated P2P key",
		"public_key", t.nodeKey.Public(),
	)

	// Create Tendermint node.
	tenderConfig := tmconfig.DefaultConfig()
	_ = viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(tendermintDataDir)
	timeoutCommit := viper.GetDuration(cfgConsensusTimeoutCommit)
	emptyBlockInterval := viper.GetDuration(cfgConsensusEmptyBlockInterval)
	tenderConfig.Genesis = viper.GetString(cfgCoreGenesisFile)
	tenderConfig.Consensus.TimeoutCommit = timeoutCommit
	tenderConfig.Consensus.SkipTimeoutCommit = viper.GetBool(cfgConsensusSkipTimeoutCommit)
	tenderConfig.Consensus.CreateEmptyBlocks = true
	tenderConfig.Consensus.CreateEmptyBlocksInterval = emptyBlockInterval
	tenderConfig.Consensus.BlockTimeIota = timeoutCommit
	if blockTimeIota := viper.GetDuration(cfgDebugConsensusBlockTimeIota); blockTimeIota > 0*time.Second {
		// Override BlockTimeIota if set.
		tenderConfig.Consensus.BlockTimeIota = blockTimeIota
	}
	tenderConfig.Instrumentation.Prometheus = true
	tenderConfig.TxIndex.Indexer = "null"
	tenderConfig.P2P.ListenAddress = viper.GetString(cfgCoreListenAddress)
	tenderConfig.P2P.ExternalAddress = viper.GetString(cfgCoreExternalAddress)
	tenderConfig.P2P.AllowDuplicateIP = true // HACK: e2e tests need this.
	tenderConfig.P2P.AddrBookStrict = !viper.GetBool(cfgDebugP2PAddrBookLenient)
	tenderConfig.RPC.ListenAddress = ""

	tendermintPV := tmpriv.LoadOrGenFilePV(tenderConfig.PrivValidatorKeyFile(), tenderConfig.PrivValidatorStateFile())
	tenderValIdent := crypto.PrivateKeyToTendermint(t.validatorKey)
	if !tenderValIdent.Equals(tendermintPV.Key.PrivKey) {
		// The private validator must have been just generated.  Force
		// it to use the oasis identity rather than the new key.
		t.Logger.Debug("fixing up tendermint private validator identity")
		tendermintPV.Key.PrivKey = tenderValIdent
		tendermintPV.Key.PubKey = tenderValIdent.PubKey()
		tendermintPV.Key.Address = tendermintPV.Key.PubKey.Address()
		tendermintPV.Save()
	}

	tmGenDoc, err := t.getGenesis(tenderConfig)
	if err != nil {
		t.Logger.Error("failed to obtain genesis document",
			"err", err,
		)
		return err
	}
	tenderminGenesisProvider := func() (*tmtypes.GenesisDoc, error) {
		return tmGenDoc, nil
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
			&tmp2p.NodeKey{PrivKey: crypto.PrivateKeyToTendermint(t.nodeKey)},
			tmproxy.NewLocalClientCreator(t.mux.Mux()),
			tenderminGenesisProvider,
			bolt.BoltDBProvider,
			tmnode.DefaultMetricsProvider(tenderConfig.Instrumentation),
			newLogAdapter(!viper.GetBool(cfgLogDebug)),
		)
		if err != nil {
			return errors.Wrap(err, "tendermint: failed to create node")
		}
		t.client = tmcli.NewLocal(t.node)

		return nil
	}

	t.isInitialized = true

	return nil
}

func (t *tendermintService) getGenesis(tenderConfig *tmconfig.Config) (*tmtypes.GenesisDoc, error) {
	var (
		genDoc   *bootstrap.GenesisDocument
		isSingle bool
	)

	genFile := tenderConfig.GenesisFile()
	if addr := viper.GetString(cfgDebugBootstrapAddress); addr != "" {
		t.Logger.Warn("The bootstrap provisioning server is NOT FOR PRODUCTION USE.")
		var (
			nodeAddr = viper.GetString(cfgCoreExternalAddress)
			nodeName = viper.GetString(cfgDebugBootstrapNodeName)
			err      error
		)
		if nodeName == "" {
			genDoc, err = bootstrap.Client(addr)
			if err != nil {
				return nil, errors.Wrap(err, "tendermint: client bootstrap failed")
			}
		} else {
			if err = common.IsAddrPort(nodeAddr); err != nil {
				return nil, errors.Wrap(err, "tendermint: malformed bootstrap validator node address")
			}
			if err = common.IsFQDN(nodeName); err != nil {
				return nil, errors.Wrap(err, "tendermint: malformed bootstrap validator node name")
			}

			validator := &bootstrap.GenesisValidator{
				PubKey:      t.validatorKey.Public(),
				Name:        common.NormalizeFQDN(nodeName),
				CoreAddress: nodeAddr,
			}
			genDoc, err = bootstrap.Validator(addr, validator)
			if err != nil {
				return nil, errors.Wrap(err, "tendermint: validator bootstrap failed")
			}
		}
	} else if _, err := os.Lstat(genFile); err != nil && os.IsNotExist(err) {
		t.Logger.Warn("Tendermint Genesis file not present. Running as a one-node validator.")
		genDoc = &bootstrap.GenesisDocument{
			Validators: []*bootstrap.GenesisValidator{
				{
					PubKey: t.validatorKey.Public(),
					Name:   "ekiden-dummy",
					Power:  10,
				},
			},
			GenesisTime: time.Now(),
		}
		isSingle = true
	} else {
		// The genesis document is just an array of GenesisValidator(s)
		// in JSON format for now.
		b, err := ioutil.ReadFile(genFile)
		if err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to read genesis doc")
		}

		genDoc = new(bootstrap.GenesisDocument)
		if err = json.Unmarshal(b, &genDoc); err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to parse genesis doc")
		}
	}

	if !isSingle {
		// So, the "right" thing to do is to use seed nodes, but those are totally
		// 100% dedicated to just seeding.  PEX works just fine off the validators,
		// so ensure that the validators exist in the address book, the hard way.
		var addrs []*tmp2p.NetAddress
		for _, v := range genDoc.Validators {
			vPubKey := crypto.PublicKeyToTendermint(&v.PubKey)
			vAddr := vPubKey.Address().String() + "@" + v.CoreAddress

			if v.PubKey.Equal(t.validatorKey.Public()) {
				// This validator entry is the current node, set the
				// node name to that specified in the genesis document.
				tenderConfig.Moniker = v.Name
				continue
			}

			tmVAddr, err := tmp2p.NewNetAddressString(vAddr)
			if err != nil {
				return nil, errors.Wrap(err, "tendermint: failed to reformat genesis validator address")
			}

			addrs = append(addrs, tmVAddr)
		}

		addrBook := tmpex.NewAddrBook(tenderConfig.P2P.AddrBookFile(), tenderConfig.P2P.AddrBookStrict)
		if err := addrBook.Start(); err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to open address book")
		}
		defer func() {
			// Can't pass tmn.NewNode() an existing address book.
			ch := addrBook.Quit()
			_ = addrBook.Stop()
			<-ch
		}()

		// Add our address to the address book, just so we can add the genesis
		// nodes.  This is somewhat silly, but there isn't any error-checking
		// done with AddOurAddress, so using the P2P ListenAddress as the IP/port
		// is totally fine.
		valPubKey := t.validatorKey.Public()
		ourPubKey := crypto.PublicKeyToTendermint(&valPubKey)
		ourLaddr, err := common.GetHostPort(tenderConfig.P2P.ListenAddress)
		if err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to parse p2p listen address")
		}
		ourAddr, err := tmp2p.NewNetAddressString(ourPubKey.Address().String() + "@" + ourLaddr)
		if err != nil {
			return nil, errors.Wrap(err, "tendermint: failed to generate our address")
		}
		addrBook.AddOurAddress(ourAddr)

		// Populate the address book with the genesis validators.
		for _, v := range addrs {
			if err = addrBook.AddAddress(v, ourAddr); err != nil {
				return nil, errors.Wrap(err, "tendermint: failed to add genesis validator to address book")
			}
		}
	}

	tmGenDoc, err := genDoc.ToTendermint()
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to create genesis doc")
	}

	return tmGenDoc, nil
}

func (t *tendermintService) worker() {
	// Subscribe to other events here as needed, no need to spawn additional
	// workers.
	evCh := make(chan interface{})
	if err := t.client.Subscribe(t.ctx, "tendermint/worker", tmtypes.EventQueryNewBlock, evCh); err != nil {
		t.Logger.Error("worker: failed to subscribe to new block events",
			"err", err,
		)
		return
	}

	for {
		select {
		case <-t.node.Quit():
			return
		case v, ok := <-evCh:
			if !ok {
				return
			}

			ev := v.(tmtypes.EventDataNewBlock)
			t.blockNotifier.Broadcast(ev.Block)
		}
	}
}

// New creates a new Tendermint service.
func New(ctx context.Context, dataDir string, identity *identity.Identity) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		blockNotifier:         pubsub.NewBroker(false),
		validatorKey:          identity.NodeKey,
		ctx:                   ctx,
		dataDir:               dataDir,
		startedCh:             make(chan struct{}),
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

func initNodeKey(dataDir string) (*signature.PrivateKey, error) {
	var k signature.PrivateKey

	if err := k.LoadPEM(filepath.Join(dataDir, "p2p.pem"), rand.Reader); err != nil {
		return nil, err
	}

	return &k, nil
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgCoreGenesisFile, "genesis.json", "tendermint core genesis file path")
		cmd.Flags().String(cfgCoreListenAddress, "tcp://0.0.0.0:26656", "tendermint core listen address")
		cmd.Flags().String(cfgCoreExternalAddress, "", "tendermint address advertised to other nodes")
		cmd.Flags().Duration(cfgConsensusTimeoutCommit, 1*time.Second, "tendermint commit timeout")
		cmd.Flags().Bool(cfgConsensusSkipTimeoutCommit, false, "skip tendermint commit timeout")
		cmd.Flags().Duration(cfgConsensusEmptyBlockInterval, 0*time.Second, "tendermint empty block interval")
		cmd.Flags().String(cfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
		cmd.Flags().Int64(cfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")
		cmd.Flags().Bool(cfgLogDebug, false, "enable tendermint debug logs (very verbose)")
		cmd.Flags().String(cfgDebugBootstrapAddress, "", "debug bootstrap server address:port")
		cmd.Flags().String(cfgDebugBootstrapNodeName, "", "debug bootstrap validator node name")
		cmd.Flags().Duration(cfgDebugConsensusBlockTimeIota, 0*time.Second, "tendermint block time iota")
		cmd.Flags().Bool(cfgDebugP2PAddrBookLenient, false, "allow non-routable addresses")
	}

	for _, v := range []string{
		cfgCoreGenesisFile,
		cfgCoreListenAddress,
		cfgCoreExternalAddress,
		cfgConsensusTimeoutCommit,
		cfgConsensusSkipTimeoutCommit,
		cfgConsensusEmptyBlockInterval,
		cfgABCIPruneStrategy,
		cfgABCIPruneNumKept,
		cfgLogDebug,
		cfgDebugBootstrapAddress,
		cfgDebugBootstrapNodeName,
		cfgDebugConsensusBlockTimeIota,
		cfgDebugP2PAddrBookLenient,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
