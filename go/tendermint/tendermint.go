package tendermint

import (
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
	tmconfig "github.com/tendermint/tendermint/config"
	tmed "github.com/tendermint/tendermint/crypto/ed25519"
	tmnode "github.com/tendermint/tendermint/node"
	tmp2p "github.com/tendermint/tendermint/p2p"
	tmpriv "github.com/tendermint/tendermint/privval"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/db/bolt"
	"github.com/oasislabs/ekiden/go/tendermint/internal/crypto"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const configDir = "config"

var _ service.TendermintService = (*tendermintService)(nil)

type tendermintService struct {
	cmservice.BaseBackgroundService

	mux           *abci.ApplicationServer
	node          *tmnode.Node
	client        tmcli.Client
	blockNotifier *pubsub.Broker

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

func (t *tendermintService) GetClient() tmcli.Client {
	if !t.isInitialized {
		panic("tendermint: GetClient() called, when no tendermint backends enabled")
	}

	return t.client
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
	t.mux, err = abci.NewApplicationServer(t.dataDir)
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

	// Initialize the node (P2P) key.  Tendermint doesn't allow
	// passing this in in a sensible format, so force load/generate
	// it in the expected location.
	if t.nodeKey, err = initNodeKey(tendermintDataDir); err != nil {
		return err
	}
	t.Logger.Debug("loaded/generated P2P key",
		"public_key", t.nodeKey.Public(),
	)

	// Create Tendermint node.
	tenderConfig := tmconfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(tendermintDataDir)

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
		tmproxy.NewLocalClientCreator(t.mux.Mux()),
		tenderminGenesisProvider,
		bolt.BoltDBProvider,
		tmnode.DefaultMetricsProvider,
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
func New(dataDir string, identity *signature.PrivateKey) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		blockNotifier:         pubsub.NewBroker(false),
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
	f := filepath.Join(dataDir, configDir, "node_key.json")
	nk, err := tmp2p.LoadOrGenNodeKey(f)
	if err != nil {
		return nil, errors.Wrap(err, "tendermint: failed to load/generate node key")
	}
	tk, ok := nk.PrivKey.(tmed.PrivKeyEd25519)
	if !ok {
		return nil, errors.New("tendermint: incompatible node key")
	}

	k := crypto.PrivateKeyFromTendermint(&tk)
	return &k, nil
}
