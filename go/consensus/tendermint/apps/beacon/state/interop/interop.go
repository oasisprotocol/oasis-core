package interop

import (
	"context"

	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// InitializeTestBeaconState must be keet in sync with tests in runtimes/consensus/state/beacon.rs.
func InitializeTestBeaconState(ctx context.Context, mkvs mkvs.Tree) error {
	state := beaconState.NewMutableState(mkvs)

	// Populate epoch.
	if err := state.SetEpoch(ctx, 42, 13); err != nil {
		return err
	}
	if err := state.SetFutureEpoch(ctx, 43, 15); err != nil {
		return err
	}

	return nil
}
