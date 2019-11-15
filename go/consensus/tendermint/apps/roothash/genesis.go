package roothash

import (
	"context"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash/state"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.RootHash

	// Store initial round timeout from the genesis document.
	rhState := roothashState.NewMutableState(ctx.State())
	rhState.SetConsensusParameters(&st.Parameters)

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes()
	for _, v := range runtimes {
		app.logger.Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		app.onNewRuntime(ctx, v, &st)
	}

	return nil
}

func (rq *rootHashQuerier) Genesis(ctx context.Context) (*roothash.Genesis, error) {
	runtimes := rq.state.Runtimes()

	// Get per-runtime blocks.
	blocks := make(map[signature.PublicKey]*block.Block)
	for _, rt := range runtimes {
		blk := *rt.CurrentBlock
		// Header should be a normal header for genesis.
		blk.Header.HeaderType = block.Normal
		// There should be no previous hash.
		blk.Header.PreviousHash.Empty()
		// No roothash messages.
		blk.Header.RoothashMessages = []*block.RoothashMessage{}
		// No storage signatures.
		blk.Header.StorageSignatures = []signature.Signature{}
		blocks[rt.Runtime.ID] = &blk
	}

	params, err := rq.state.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	genesis := &roothash.Genesis{
		Parameters: *params,
		Blocks:     blocks,
	}
	return genesis, nil
}
