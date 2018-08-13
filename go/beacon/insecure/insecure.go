// Package insecure implements the insecure (deterministic) random beacon.
//
// This implementation MUST NOT be used in a production setting.
package insecure

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

// BackendName is the name of this implementation.
const BackendName = "insecure"

var (
	_ api.Backend = (*insecureDummy)(nil)

	dummyContext = []byte("EkB-Dumm")
)

type insecureDummy struct {
	logger   *logging.Logger
	notifier *pubsub.Broker

	lastEpoch epochtime.EpochTime
}

func (r *insecureDummy) GetBeacon(ctx context.Context, epoch epochtime.EpochTime) ([]byte, error) {
	// Simulate a per-epoch shared random beacon value with
	// `SHA512_256("EkB-Dumm" | to_le_64(epoch))` as it is a reasonable
	// approximation of a well behaved random beacon, just without the
	// randomness.
	seed := make([]byte, len(dummyContext)+8)
	copy(seed[:], dummyContext)
	binary.LittleEndian.PutUint64(seed[len(dummyContext):], uint64(epoch))
	ret := sha512.Sum512_256(seed)

	return ret[:], nil
}

func (r *insecureDummy) WatchBeacons() (<-chan *api.GenerateEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.GenerateEvent)
	sub := r.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *insecureDummy) worker(timeSource epochtime.Backend) {
	epochEvents, sub := timeSource.WatchEpochs()
	defer sub.Close()
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

		b, _ := r.GetBeacon(context.Background(), newEpoch)

		r.logger.Debug("worker: generated beacon",
			"epoch", newEpoch,
			"beacon", hex.EncodeToString(b),
		)

		r.notifier.Broadcast(&api.GenerateEvent{
			Epoch:  newEpoch,
			Beacon: b,
		})

		r.lastEpoch = newEpoch
	}
}

// New constructs a new insecure dummy random beacon Backend instance.
//
// Returned values are totally deterministc and MUST NOT be used in a
// production setting.
func New(timeSource epochtime.Backend) api.Backend {
	r := &insecureDummy{
		logger:    logging.GetLogger("beacon/insecure"),
		notifier:  pubsub.NewBroker(true),
		lastEpoch: epochtime.EpochInvalid,
	}

	go r.worker(timeSource)

	return r
}
