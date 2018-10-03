package tendermint

import (
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	tmabci "github.com/tendermint/tendermint/abci/types"
	tmconfig "github.com/tendermint/tendermint/config"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmpriv "github.com/tendermint/tendermint/privval"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/db/bolt"
	"github.com/oasislabs/ekiden/go/tendermint/internal/crypto"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	configDir = "config"

	cfgConsensusTimeoutCommit      = "tendermint.consensus.timeout_commit"
	cfgConsensusSkipTimeoutCommit  = "tendermint.consensus.skip_timeout_commit"
	cfgConsensusEmptyBlockInterval = "tendermint.consensus.empty_block_interval"

	cfgABCIPruneStrategy = "tendermint.abci.prune.strategy"
	cfgABCIPruneNumKept  = "tendermint.abci.prune.num_kept"
)

var (
	_ service.TendermintService = (*tendermintService)(nil)

	flagConsensusTimeoutCommit      time.Duration
	flagConsensusSkipTimeoutCommit  bool
	flagConsensusEmptyBlockInterval time.Duration

	flagABCIPruneStrategy string
	flagABCIPruneNumKept  int64
)

type tendermintService struct {
	cmservice.BaseBackgroundService

	mux           *abci.ApplicationServer
	node          *tmnode.Node
	client        tmcli.Client
	blockNotifier *pubsub.Broker

	cmd                      *cobra.Command
	validatorKey             *signature.PrivateKey
	nodeKey                  *signature.PrivateKey
	dataDir                  string
	isInitialized, isStarted bool
	startedCh                chan struct{}
}

func (t *tendermintService) Start() error {
	if !t.isInitialized {
		return nil
	}

	if err := t.mux.Start(); err != nil {
		return err
	}
	if err := t.node.Start(); err != nil {
		return errors.Wrap(err, "tendermint: failed to start service")
	}

	go t.worker()

	close(t.startedCh)
	t.isStarted = true

	return nil
}

func (t *tendermintService) Quit() <-chan struct{} {
	if !t.isInitialized {
		return make(chan struct{})
	}

	return t.node.Quit()
}

func (t *tendermintService) Stop() {
	if !t.isInitialized {
		return
	}

	if err := t.node.Stop(); err != nil {
		t.Logger.Error("Error on stopping node", err)
	}

	t.mux.Stop()
}

func (t *tendermintService) Started() <-chan struct{} {
	return t.startedCh
}

func (t *tendermintService) BroadcastTx(tag byte, tx interface{}) error {
	if !t.isInitialized {
		panic("tendermint: BroadcastTx() called, when no tendermint backends enabled")
	}

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
	if !t.isInitialized {
		panic("tendermint: Query() called, when no tendermint backends enabled")
	}

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
	return t.node.EventBus().Subscribe(ctx, subscriber, query, out)
}

func (t *tendermintService) Unsubscribe(ctx context.Context, subscriber string, query tmpubsub.Query) error {
	return t.node.EventBus().Unsubscribe(ctx, subscriber, query)
}

func (t *tendermintService) Genesis() (*tmrpctypes.ResultGenesis, error) {
	return t.client.Genesis()
}

func (t *tendermintService) RegisterApplication(app abci.Application) error {
	if !t.isInitialized {
		t.Logger.Debug("Initializing tendermint local node/mux.")
		if err := t.lazyInit(); err != nil {
			return err
		}
	}
	if t.isStarted {
		return errors.New("tendermint: service already started")
	}

	return t.mux.Register(app)
}

func (t *tendermintService) ForceInitialize() error {
	var err error
	if !t.isInitialized {
		t.Logger.Debug("Force-initializing tendermint local node.")
		err = t.lazyInit()
	}

	return err
}

func (t *tendermintService) GetBlock(height int64) (*tmtypes.Block, error) {
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
	pruneStrat, _ := t.cmd.Flags().GetString(cfgABCIPruneStrategy)
	if err = pruneCfg.Strategy.FromString(pruneStrat); err != nil {
		return err
	}
	pruneNumKept, _ := t.cmd.Flags().GetInt64(cfgABCIPruneNumKept)
	pruneCfg.NumKept = pruneNumKept

	t.mux, err = abci.NewApplicationServer(t.dataDir, &pruneCfg)
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
	timeoutCommit, _ := t.cmd.Flags().GetDuration(cfgConsensusTimeoutCommit)
	timeoutCommitMsec := int(timeoutCommit / time.Millisecond)
	emptyBlockInterval, _ := t.cmd.Flags().GetDuration(cfgConsensusEmptyBlockInterval)
	tenderConfig.Consensus.TimeoutCommit = timeoutCommitMsec
	tenderConfig.Consensus.SkipTimeoutCommit, _ = t.cmd.Flags().GetBool(cfgConsensusSkipTimeoutCommit)
	tenderConfig.Consensus.CreateEmptyBlocks = true
	tenderConfig.Consensus.CreateEmptyBlocksInterval = int(math.Ceil(emptyBlockInterval.Seconds()))
	tenderConfig.Consensus.BlockTimeIota = timeoutCommitMsec
	tenderConfig.Instrumentation.Prometheus = true

	tendermintPV := tmpriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile())
	tenderValIdent := crypto.PrivateKeyToTendermint(t.validatorKey)
	if !tenderValIdent.Equals(tendermintPV.PrivKey) {
		// The private validator must have been just generated.  Force
		// it to use the oasis identity rather than the new key.
		t.Logger.Debug("fixing up tendermint private validator identity")
		tendermintPV.PrivKey = tenderValIdent
		tendermintPV.PubKey = tenderValIdent.PubKey()
		tendermintPV.Address = tendermintPV.PubKey.Address()
		tendermintPV.Save()
	}

	var tenderminGenesisProvider tmnode.GenesisDocProvider
	genFile := tenderConfig.GenesisFile()
	if _, err = os.Lstat(genFile); err != nil && os.IsNotExist(err) {
		t.Logger.Warn("Tendermint Genesis file not present. Running as a one-node validator.")
		genDoc := tmtypes.GenesisDoc{
			ChainID:         "0xa515",
			GenesisTime:     time.Now(),
			ConsensusParams: tmtypes.DefaultConsensusParams(),
		}
		genDoc.Validators = []tmtypes.GenesisValidator{{
			PubKey: tendermintPV.GetPubKey(),
			Power:  10,
		}}
		tenderminGenesisProvider = func() (*tmtypes.GenesisDoc, error) {
			return &genDoc, nil
		}
	} else {
		tenderminGenesisProvider = tmnode.DefaultGenesisDocProviderFunc(tenderConfig)
	}

	t.node, err = tmnode.NewNode(tenderConfig,
		tendermintPV,
		&tmp2p.NodeKey{PrivKey: crypto.PrivateKeyToTendermint(t.nodeKey)},
		tmproxy.NewLocalClientCreator(t.mux.Mux()),
		tenderminGenesisProvider,
		bolt.BoltDBProvider,
		tmnode.DefaultMetricsProvider(tenderConfig.Instrumentation),
		&abci.LogAdapter{
			Logger:           logging.GetLogger("tendermint"),
			IsTendermintCore: true,
		},
	)
	if err != nil {
		return errors.Wrap(err, "tendermint: failed to create node")
	}
	t.client = tmcli.NewLocal(t.node)

	t.isInitialized = true

	return nil
}

func (t *tendermintService) worker() {
	// Subscribe to other events here as needed, no need to spawn additional
	// workers.
	evCh := make(chan interface{})
	if err := t.client.Subscribe(context.Background(), "tendermint/worker", tmtypes.EventQueryNewBlock, evCh); err != nil {
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
func New(cmd *cobra.Command, dataDir string, identity *signature.PrivateKey) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		blockNotifier:         pubsub.NewBroker(false),
		cmd:                   cmd,
		validatorKey:          identity,
		dataDir:               dataDir,
		startedCh:             make(chan struct{}),
	}
}

func initDataDir(dataDir string) error {
	subDirs := []string{
		configDir,

		// This *could* also create "data", but both the built in and
		// BoltDB providers handle it being missing gracefully.
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().DurationVar(&flagConsensusTimeoutCommit, cfgConsensusTimeoutCommit, 1*time.Second, "tendermint commit timeout")
	cmd.Flags().BoolVar(&flagConsensusSkipTimeoutCommit, cfgConsensusSkipTimeoutCommit, false, "skip tendermint commit timeout")
	cmd.Flags().DurationVar(&flagConsensusEmptyBlockInterval, cfgConsensusEmptyBlockInterval, 0, "tendermint empty block interval")
	cmd.Flags().StringVar(&flagABCIPruneStrategy, cfgABCIPruneStrategy, abci.PruneDefault, "ABCI state pruning strategy")
	cmd.Flags().Int64Var(&flagABCIPruneNumKept, cfgABCIPruneNumKept, 3600, "ABCI state versions kept (when applicable)")

	for _, v := range []string{
		cfgConsensusTimeoutCommit,
		cfgConsensusSkipTimeoutCommit,
		cfgConsensusEmptyBlockInterval,
		cfgABCIPruneStrategy,
		cfgABCIPruneNumKept,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
