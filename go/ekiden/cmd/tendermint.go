package cmd

import (
	"github.com/oasislabs/ekiden/go/common/logging"
	adapter "github.com/oasislabs/ekiden/go/tendermint/abci"

	"github.com/spf13/viper"
	tendermintConfig "github.com/tendermint/tendermint/config"
	tendermintNode "github.com/tendermint/tendermint/node"
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

func newTendermintService() (*tendermintAdapter, error) {
	tenderConfig := tendermintConfig.DefaultConfig()
	viper.Unmarshal(&tenderConfig)
	tenderConfig.SetRoot(dataDir)
	tenderLog := &adapter.LogAdapter{logging.GetLogger("tendermint")}
	node, err := tendermintNode.DefaultNewNode(tenderConfig, tenderLog)
	if err != nil {
		return nil, err
	}
	return &tendermintAdapter{node}, nil
}
