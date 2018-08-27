package tendermint

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
	tmconfig "github.com/tendermint/tendermint/config"
	tmnode "github.com/tendermint/tendermint/node"
	tmpriv "github.com/tendermint/tendermint/privval"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/db/bolt"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var (
	errAlreadyStarted = errors.New("tendermint: service already started")

	_ service.TendermintService = (*tendermintService)(nil)
)

type tendermintService struct {
	cmservice.BaseBackgroundService

	mux            *abci.ApplicationServer
	node           *tmnode.Node
	internalClient tmcli.Client
	blockNotifier  *pubsub.Broker

	dataDir                  string
	isInitialized, isStarted bool
}

func (t *tendermintService) Start() error {
	if !t.isInitialized {
		return nil
	}

	if err := t.mux.Start(); err != nil {
		return err
	}
	if err := t.node.Start(); err != nil {
		return err
	}
	t.internalClient = t.GetClient()

	go t.worker()

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

func (t *tendermintService) GetClient() tmcli.Client {
	if !t.isInitialized {
		panic("tendermint: GetClient() called, when no tendermint backends enabled")
	}

	return tmcli.NewLocal(t.node)
}

func (t *tendermintService) RegisterApplication(app abci.Application) error {
	if !t.isInitialized {
		t.Logger.Debug("Initializing tendermint local node/mux.")
		if err := t.lazyInit(); err != nil {
			return err
		}
	}
	if t.isStarted {
		return errAlreadyStarted
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

func (t *tendermintService) WatchBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription) {
	typedCh := make(chan *tmtypes.Block)
	sub := t.blockNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
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

	// Create Tendermint node.
	tenderConfig := tmconfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(tendermintDataDir)

	tendermintPV := tmpriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile())
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
		return err
	}

	t.isInitialized = true

	return nil
}

func (t *tendermintService) worker() {
	// Subscribe to other events here as needed, no need to spawn additional
	// workers.
	evCh := make(chan interface{})
	if err := t.internalClient.Subscribe(context.Background(), "tendermint/worker", tmtypes.EventQueryNewBlock, evCh); err != nil {
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
func New(dataDir string) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		blockNotifier:         pubsub.NewBroker(false),
		dataDir:               dataDir,
	}
}

func initDataDir(dataDir string) error {
	subDirs := []string{
		"config",

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
