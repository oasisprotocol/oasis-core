// Package beacon implements the RandomBeacon.
package beacon

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime"
)

// ErrBeaconNotAvailable is the error returned when a beacon is not
// available for the requested epoch for any reason.
var ErrBeaconNotAvailable = errors.New("beacon: Beacon not available")

// BeaconSize is the size of the beacon in bytes.
const BeaconSize = 32

// RandomBeacon is a RandomBeacon implementation.
type RandomBeacon interface {
	// GetBeacon gets the beacon for the provided epoch.
	GetBeacon(epochtime.EpochTime) ([]byte, error)

	// WatchBeacons returns a channel that produces a stream of
	// GenerateEvent.  Upon subscription, the most recently generate
	// beacon will be sent immediately if available.
	WatchBeacons() (<-chan *GenerateEvent, *pubsub.Subscription)
}

// GenerateEvent is the event that is returned via WatchBeacons to
// signify beacon generation.
type GenerateEvent struct {
	Epoch  epochtime.EpochTime
	Beacon []byte
}

func subscribeTypedGenerateEvent(notifier *pubsub.Broker) (<-chan *GenerateEvent, *pubsub.Subscription) {
	typedCh := make(chan *GenerateEvent)
	sub := notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}
