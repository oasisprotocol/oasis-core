package cmd

import (
	"os"
	"time"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/apps"

	"github.com/spf13/viper"
	tendermintConfig "github.com/tendermint/tendermint/config"
	tendermintNode "github.com/tendermint/tendermint/node"
	tendermintPriv "github.com/tendermint/tendermint/privval"
	tendermintProxy "github.com/tendermint/tendermint/proxy"
	tendermintTypes "github.com/tendermint/tendermint/types"
)

// Adapter for tendermint Nodes to be managed by the ekiden service mux.
type tendermintAdapter struct {
	*tendermintNode.Node
}

// discard error response.
func (t *tendermintAdapter) Stop() {
	if e := t.Node.Stop(); e != nil {
		t.Logger.Error("Error on stopping", e)
	}
}

func (t *tendermintAdapter) Cleanup() {
	_ = t.Reset()
}

func newTendermintService(mux *abci.ApplicationServer) (*tendermintAdapter, error) {
	// Register Oasis ABCI applications with the application server.
	mux.Register(apps.NewRegistryApplication())

	// Instantiate the Tendermint node.
	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(dataDir)

	tendermintPV := tendermintPriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile())
	var tenderminGenesisProvider tendermintNode.GenesisDocProvider
	genFile := tenderConfig.GenesisFile()
	_, err := os.Lstat(genFile)
	if err != nil && os.IsNotExist(err) {
		rootLog.Warn("Tendermint Genesis file not present. Running as a one-node validator.")
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
		&abci.LogAdapter{logging.GetLogger("tendermint")})
	if err != nil {
		return nil, err
	}
	return &tendermintAdapter{node}, nil
}
