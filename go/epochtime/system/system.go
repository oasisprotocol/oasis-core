// Package system implements the real time clock based epochtime backend.
package system

import (
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
)

// BackendName is the name of this implementation.
const BackendName = "system"

var (
	ekidenEpochBase               = time.Unix(api.EkidenEpoch, 0)
	_               (api.Backend) = (*systemBackend)(nil)
)

type systemBackend struct {
	sync.Mutex

	logger   *logging.Logger
	notifier *pubsub.Broker

	lastNotified api.EpochTime
	interval     int64
}

func (s *systemBackend) GetEpoch(ctx context.Context) (api.EpochTime, uint64, error) {
	epoch, elapsed := getEpochAt(time.Now(), s.interval)
	return epoch, elapsed, nil
}

func (s *systemBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := s.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (s *systemBackend) worker() {
	t := time.NewTicker(1 * time.Second)
	for {
		<-t.C
		if newEpoch, _, _ := s.GetEpoch(context.Background()); newEpoch != s.lastNotified {
			s.logger.Debug("epoch transition",
				"prev_epoch", s.lastNotified,
				"epoch", newEpoch,
			)

			s.Lock()
			s.lastNotified = newEpoch
			s.Unlock()

			s.notifier.Broadcast(newEpoch)
		}
	}
}

// New constructs a new RTC backed epochtime Backend instance, with the
// specified epoch interval.
func New(interval int64) (api.Backend, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("epochtime/system: invalid epoch interval: %v", interval)
	}

	s := &systemBackend{
		logger:   logging.GetLogger("epochtime/system"),
		interval: interval,
	}
	s.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		epoch, _, err := s.GetEpoch(context.Background())
		if err != nil {
			panic(err)
		}

		// Iff the notifications for the current epoch went out,
		// broadcast the current epoch on subscribe, otherwise,
		// assume that the event mechanism will handle it.
		s.Lock()
		defer s.Unlock()

		if epoch == s.lastNotified {
			ch.In() <- epoch
		}
	})

	s.logger.Debug("initialized",
		"backend", BackendName,
		"interval", interval,
	)

	go s.worker()

	return s, nil
}

func getEpochAt(at time.Time, interval int64) (epoch api.EpochTime, elapsed uint64) {
	delta := int64(at.Sub(ekidenEpochBase).Seconds())
	if delta < 0 {
		panic("epochtime/system: time predates EkidenEpoch")
	}

	epoch = api.EpochTime(delta / interval)
	elapsed = uint64(delta % interval)
	return
}
