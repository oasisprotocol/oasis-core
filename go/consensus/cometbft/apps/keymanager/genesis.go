package keymanager

import (
	"encoding/json"

	"github.com/cometbft/cometbft/abci/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

func (app *keymanagerApplication) InitChain(ctx *tmapi.Context, req types.RequestInitChain, doc *genesis.Document) error {
	b, _ := json.Marshal(doc.KeyManager)
	ctx.Logger().Debug("InitChain: Genesis state",
		"state", string(b),
	)

	for _, ext := range app.exts {
		if err := ext.InitChain(ctx, req, doc); err != nil {
			return err
		}
	}

	return nil
}
