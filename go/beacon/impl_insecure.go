package beacon

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime"
)

var (
	_ RandomBeacon = (*InsecureDummyRandomBeacon)(nil)

	dummyBeaconContext = []byte("EkB-Dumm")
)

// InsecureDummyRandomBeacon is a INSECURE RandomBeacon implementation
// inteded for testing purposes.  Returned values are totally deterministc
// and MUST NOT be used in a production setting.
type InsecureDummyRandomBeacon struct {
	logger   *logging.Logger
	notifier *pubsub.Broker

	lastEpoch epochtime.EpochTime
}

// GetBeacon gets the beacon for the provided epoch.
func (r *InsecureDummyRandomBeacon) GetBeacon(epoch epochtime.EpochTime) ([]byte, error) {
	// Simulate a per-epoch shared random beacon value with
	// `SHA512_256("EkB-Dumm" | to_le_64(epoch))` as it is a reasonable
	// approximation of a well behaved random beacon, just without the
	// randomness.
	seed := make([]byte, len(dummyBeaconContext)+8)
	copy(seed[:], dummyBeaconContext)
	binary.LittleEndian.PutUint64(seed[len(dummyBeaconContext):], uint64(epoch))
	ret := sha512.Sum512_256(seed)

	return ret[:], nil
}

// WatchBeacons returns a channel that produces a stream of GenerateEvent.
// Upon subscription, the most recently generate beacon will be sent
// immediately if available.
func (r *InsecureDummyRandomBeacon) WatchBeacons() <-chan *GenerateEvent {
	return subscribeTypedGenerateEvent(r.notifier)
}

func (r *InsecureDummyRandomBeacon) worker(timeSource epochtime.TimeSource) {
	epochEvents := timeSource.WatchEpochs()
	for {
		newEpoch, ok := <-epochEvents
		if !ok {
			r.logger.Debug("worker: terminating")
			return
		}

		r.logger.Debug("worker: epoch transition",
			"prev_epoch", r.lastEpoch,
			"epoch", newEpoch,
		)

		if newEpoch == r.lastEpoch {
			continue
		}

		b, _ := r.GetBeacon(newEpoch)

		r.logger.Debug("worker: generated beacon",
			"epoch", newEpoch,
			"beacon", hex.EncodeToString(b),
		)

		r.notifier.Broadcast(&GenerateEvent{
			Epoch:  newEpoch,
			Beacon: b,
		})

		r.lastEpoch = newEpoch
	}
}

// NewInsecureDummyRandomBeacon constructs a new InsecureDummyRandomBeacon
// instance.
func NewInsecureDummyRandomBeacon(timeSource epochtime.TimeSource) *InsecureDummyRandomBeacon {
	r := &InsecureDummyRandomBeacon{
		logger:    logging.GetLogger("InsecureDummyRandomBeacon"),
		notifier:  pubsub.NewBroker(true),
		lastEpoch: epochtime.EpochInvalid,
	}

	go r.worker(timeSource)

	return r
}
