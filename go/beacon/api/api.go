// Package api implements the random beacon API.
package api

import (
	"context"
	"errors"
)

// ErrBeaconNotAvailable is the error returned when a beacon is not
// available for the requested height for any reason.
var ErrBeaconNotAvailable = errors.New("beacon: random beacon not available")

// BeaconSize is the size of the beacon in bytes.
const BeaconSize = 32

// Backend is a random beacon implementation.
type Backend interface {
	// GetBeacon gets the beacon for the provided block height.
	// Calling this method with height `0`, should return the
	// beacon for latest finalized block.
	GetBeacon(context.Context, int64) ([]byte, error)
}

// Config is the per-backend common configuration.
type Config struct {
	// DebugDeterministic is true iff the output should be deterministic.
	DebugDeterministic bool
}
