// Package api implements the random beacon API.
package api

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	// ModuleName is a unique module name for the beacon module.
	ModuleName = "beacon"

	// BeaconSize is the size of the beacon in bytes.
	BeaconSize = 32
)

// ErrBeaconNotAvailable is the error returned when a beacon is not
// available for the requested height for any reason.
var ErrBeaconNotAvailable = errors.New(ModuleName, 1, "beacon: random beacon not available")

// Backend is a random beacon implementation.
type Backend interface {
	// GetBeacon gets the beacon for the provided block height.
	// Calling this method with height `0`, should return the
	// beacon for latest finalized block.
	GetBeacon(context.Context, int64) ([]byte, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(context.Context, int64) (*Genesis, error)
}

// Genesis is the beacon genesis state.
type Genesis struct {
	// Parameters are the beacon consensus parameters.
	Parameters ConsensusParameters `json:"params"`
}

// ConsensusParameters are the beacon consensus parameters.
type ConsensusParameters struct {
	// DebugDeterministic is true iff the output should be deterministic.
	DebugDeterministic bool `json:"debug_deterministic,omitempty"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	unsafeFlags := g.Parameters.DebugDeterministic
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("beacon: sanity check failed: one or more unsafe debug flags set")
	}

	return nil
}
