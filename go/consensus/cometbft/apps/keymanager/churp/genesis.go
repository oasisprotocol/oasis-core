package churp

import (
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// InitChain implements api.Extension.
func (ext *churpExt) InitChain(ctx *tmapi.Context, _ types.RequestInitChain, _ *genesis.Document) error {
	state := churpState.NewMutableState(ctx.State())

	if err := state.SetConsensusParameters(ctx, &churp.DefaultConsensusParameters); err != nil {
		return fmt.Errorf("cometbft/keymanager/churp: failed to set consensus parameters: %w", err)
	}

	return nil
}
