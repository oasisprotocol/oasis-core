// Package api implements the random beacon API.
package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/pubsub"
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
	// beacon for latest finished block.
	GetBeacon(context.Context, int64) ([]byte, error)

	// WatchBeacons returns a channel that produces a stream of
	// GenerateEvent.  Upon subscription, the most recently generate
	// beacon will be sent immediately if available.
	WatchBeacons() (<-chan *GenerateEvent, *pubsub.Subscription)
}

// GenerateEvent is the event that is returned via WatchBeacons to
// signify beacon generation.
type GenerateEvent struct {
	Beacon []byte `codec:"beacon"`
}
