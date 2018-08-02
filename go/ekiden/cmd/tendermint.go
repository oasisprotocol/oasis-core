package cmd

import (
	"github.com/oasislabs/ekiden/go/common/logging"
	adapter "github.com/oasislabs/ekiden/go/tendermint/abci"

	"github.com/spf13/viper"
	tendermintConfig "github.com/tendermint/tendermint/config"
	tendermintNode "github.com/tendermint/tendermint/node"
	tendermintPriv "github.com/tendermint/tendermint/privval"
	tendermintProxy "github.com/tendermint/tendermint/proxy"
)

// Adapter for tendermint Nodes to be managed by the ekiden service mux
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

func newTendermintService(mux *adapter.ApplicationServer) (*tendermintAdapter, error) {
	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(dataDir)

	node, err := tendermintNode.NewNode(tenderConfig,
		tendermintPriv.LoadOrGenFilePV(tenderConfig.PrivValidatorFile()),
		tendermintProxy.NewLocalClientCreator(mux.Mux()),
		tendermintNode.DefaultGenesisDocProviderFunc(tenderConfig),
		tendermintNode.DefaultDBProvider,
		tendermintNode.DefaultMetricsProvider,
		&adapter.LogAdapter{Logger: logging.GetLogger("tendermint")})
	if err != nil {
		return nil, err
	}
	return &tendermintAdapter{node}, nil
}
