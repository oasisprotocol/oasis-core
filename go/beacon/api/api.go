// Package api implements the random beacon API.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/errors"
)

const (
	// BackendName is a unique backend name for the beacon backend.
	BackendName = "beacon"

	// BeaconSize is the size of the beacon in bytes.
	BeaconSize = 32
)

// ErrBeaconNotAvailable is the error returned when a beacon is not
// available for the requested height for any reason.
var ErrBeaconNotAvailable = errors.New(BackendName, 1, "beacon: random beacon not available")

// Backend is a random beacon implementation.
type Backend interface {
	// GetBeacon gets the beacon for the provided block height.
	// Calling this method with height `0`, should return the
	// beacon for latest finalized block.
	GetBeacon(context.Context, int64) ([]byte, error)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(context.Context, int64) (*Genesis, error)
}

// Genesis is the beacon genesis state.
type Genesis struct {
	// Parameters are the beacon consensus parameters.
	Parameters ConsensusParameters `json:"params"`
}

// ConsensusParameters are the beacon consensus parameters.
type ConsensusParameters struct {
	// DebugDeterministic is true iff the output should be deterministic.
	DebugDeterministic bool `json:"debug_deterministic"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	return nil
}
