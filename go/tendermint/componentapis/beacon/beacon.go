package beacon

import (
	"github.com/tendermint/iavl"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

// Backend is a random beacon implementation.
type Backend interface {
	// GetBeaconABCI gets the beacon for the provided epoch.
	GetBeaconABCI(*abci.Context, *iavl.MutableTree, epochtime.EpochTime) ([]byte, error)
}
