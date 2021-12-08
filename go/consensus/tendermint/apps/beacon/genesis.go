package beacon

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

func (app *beaconApplication) InitChain(ctx *api.Context, req types.RequestInitChain, doc *genesis.Document) error {
	params := &doc.Beacon.Parameters

	// Note: If we ever decide that we need a beacon for the 0th epoch
	// (that is *only* for the genesis state), it should be initiailized
	// here.
	//
	// It is not super important for now as the epoch will transition
	// immediately on the first block under normal circumstances.
	state := beaconState.NewMutableState(ctx.State())

	if err := state.SetConsensusParameters(ctx, params); err != nil {
		return fmt.Errorf("beacon: failed to set consensus parameters: %w", err)
	}

	// Do the per-backend genesis initialization.
	if err := app.doInitBackend(params); err != nil {
		return fmt.Errorf("beacon: failed to initialize backend: %w", err)
	}
	if err := app.backend.OnInitChain(ctx, state, params, doc); err != nil {
		return fmt.Errorf("beacon: failed to handle per-backend initialization: %w", err)
	}

	return nil
}

func (app *beaconApplication) doInitBackend(params *beacon.ConsensusParameters) error {
	if app.backend != nil {
		return nil
	}

	backendName := params.Backend
	switch backendName {
	case beacon.BackendInsecure:
		app.backend = &backendInsecure{app}
	case beacon.BackendVRF:
		app.backend = &backendVRF{app}
	default:
		return fmt.Errorf("beacon: unsupported backend: '%s'", backendName)
	}

	return nil
}

func (bq *beaconQuerier) Genesis(ctx context.Context) (*beacon.Genesis, error) {
	params, err := bq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}
	epoch, _, err := bq.state.GetEpoch(ctx)
	if err != nil {
		return nil, err
	}

	genesis := &beacon.Genesis{
		Base:       epoch,
		Parameters: *params,
	}
	return genesis, nil
}
