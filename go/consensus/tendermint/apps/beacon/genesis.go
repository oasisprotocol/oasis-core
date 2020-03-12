package beacon

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/beacon/state"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

func (app *beaconApplication) InitChain(ctx *abciAPI.Context, req types.RequestInitChain, doc *genesis.Document) error {
	// Note: If we ever decide that we need a beacon for the 0th epoch
	// (that is *only* for the genesis state), it should be initiailized
	// here.
	//
	// It is not super important for now as the epoch will transition
	// immediately on the first block under normal circumstances.
	state := beaconState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &doc.Beacon.Parameters); err != nil {
		return fmt.Errorf("failed to set consensus parameters: %w", err)
	}

	if doc.Beacon.Parameters.DebugDeterministic {
		ctx.Logger().Warn("Determistic beacon entropy is NOT FOR PRODUCTION USE")
	}
	return nil
}

func (bq *beaconQuerier) Genesis(ctx context.Context) (*beacon.Genesis, error) {
	params, err := bq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	genesis := &beacon.Genesis{
		Parameters: *params,
	}
	return genesis, nil
}
