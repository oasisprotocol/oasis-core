package tendermint

import (
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
	"github.com/oasislabs/ekiden/go/tendermint/apps"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var (
	_ service.TendermintService = (*tendermintServiceImpl)(nil)
)

type tendermintServiceImpl struct {
	cmservice.BaseBackgroundService

	// Ekiden ABCI application mux.
	mux *abci.ApplicationServer

	// Tendermint node.
	node *tendermintNode.Node
}

func (t *tendermintServiceImpl) Start() error {
	if err := t.mux.Start(); err != nil {
		return err
	}

	if err := t.node.Start(); err != nil {
		return err
	}

	return nil
}

func (t *tendermintServiceImpl) Quit() <-chan struct{} {
	return t.node.Quit()
}

func (t *tendermintServiceImpl) Stop() {
	if err := t.node.Stop(); err != nil {
		t.Logger.Error("Error on stopping node", err)
	}

	t.mux.Stop()
}

func (t *tendermintServiceImpl) GetClient() tmcli.Client {
	return tmcli.NewLocal(t.node)
}

// New creates a new Tendermint service.
func New(dataDir string) (service.TendermintService, error) {
	svc := *cmservice.NewBaseBackgroundService("tendermint")

	// Create Tendermint application mux.
	mux, err := abci.NewApplicationServer(dataDir)
	if err != nil {
		return nil, err
	}

	// Register Ekiden ABCI applications with the application mux.
	mux.Register(apps.NewRegistryApplication())

	// Create Tendermint node.
	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(dataDir)

	tendermintPV := tendermintPriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile())
	var tenderminGenesisProvider tendermintNode.GenesisDocProvider
	genFile := tenderConfig.GenesisFile()
	_, err = os.Lstat(genFile)
	if err != nil && os.IsNotExist(err) {
		svc.Logger.Warn("Tendermint Genesis file not present. Running as a one-node validator.")
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

	node, err := tendermintNode.NewNode(tenderConfig,
		tendermintPV,
		tendermintProxy.NewLocalClientCreator(mux.Mux()),
		tenderminGenesisProvider,
		tendermintNode.DefaultDBProvider,
		tendermintNode.DefaultMetricsProvider,
		&abci.LogAdapter{
			Logger:           logging.GetLogger("tendermint"),
			IsTendermintCore: true,
		},
	)
	if err != nil {
		return nil, err
	}

	return &tendermintServiceImpl{
		BaseBackgroundService: svc,
		mux:  mux,
		node: node,
	}, nil
}
