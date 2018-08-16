package tendermint

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/viper"
	tendermintConfig "github.com/tendermint/tendermint/config"
	tendermintNode "github.com/tendermint/tendermint/node"
	tendermintPriv "github.com/tendermint/tendermint/privval"
	tendermintProxy "github.com/tendermint/tendermint/proxy"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tendermintTypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmservice "github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var (
	errAlreadyStarted = errors.New("tendermint: service already started")

	_ service.TendermintService = (*tendermintService)(nil)
)

type tendermintService struct {
	cmservice.BaseBackgroundService

	mux  *abci.ApplicationServer
	node *tendermintNode.Node

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

	// Create Tendermint node.
	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(t.dataDir)

	tendermintPV := tendermintPriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile())
	var tenderminGenesisProvider tendermintNode.GenesisDocProvider
	genFile := tenderConfig.GenesisFile()
	if _, err = os.Lstat(genFile); err != nil && os.IsNotExist(err) {
		t.Logger.Warn("Tendermint Genesis file not present. Running as a one-node validator.")
		genDoc := tendermintTypes.GenesisDoc{
			ChainID:         "0xa515",
			GenesisTime:     time.Now(),
			ConsensusParams: tendermintTypes.DefaultConsensusParams(),
		}
		genDoc.Validators = []tendermintTypes.GenesisValidator{{
			PubKey: tendermintPV.GetPubKey(),
			Power:  10,
		}}
		tenderminGenesisProvider = func() (*tendermintTypes.GenesisDoc, error) {
			return &genDoc, nil
		}
	} else {
		tenderminGenesisProvider = tendermintNode.DefaultGenesisDocProviderFunc(tenderConfig)
	}

	t.node, err = tendermintNode.NewNode(tenderConfig,
		tendermintPV,
		tendermintProxy.NewLocalClientCreator(t.mux.Mux()),
		tenderminGenesisProvider,
		tendermintNode.DefaultDBProvider,
		tendermintNode.DefaultMetricsProvider,
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

// New creates a new Tendermint service.
func New(dataDir string) service.TendermintService {
	return &tendermintService{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		dataDir:               dataDir,
	}
}
