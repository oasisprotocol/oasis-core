// Package epochtime implements the Oasis timekeeping.
package epochtime

import (
	"sync"
	"time"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
)

// EpochTime is the number of intervals (epochs) since a fixed instant
// in time (epoch date).
type EpochTime uint64

const (
	// EkidenEpoch is the epoch date, as the number of seconds since
	// the UNIX epoch.
	EkidenEpoch int64 = 1514764800 // 2018-01-01T00:00:00+00:00

	// EpochInterval is the epoch interval in seconds.
	EpochInterval = 86400 // 1 day

	// EpochInvalid is the placeholder invalid epoch.
	EpochInvalid EpochTime = 0xffffffffffffffff // ~50 quadrillion years away.
)

var (
	ekidenEpochBase            = time.Unix(EkidenEpoch, 0)
	_               TimeSource = (*MockTimeSource)(nil)
)

// TimeSource is a timekeeping implementation.
type TimeSource interface {
	// GetEpoch returns the current epoch and the number of seconds
	// since the begining of the current epoch.
	GetEpoch() (epoch EpochTime, elapsed uint64)

	// WatchEpochs returns a channel that produces a stream of messages
	// on epoch transitions.
	WatchEpochs() <-chan EpochTime
}

// SystemTimeSource is a TimeSource based on the system's real time clock.
type SystemTimeSource struct {
	logger   *logging.Logger
	notifier *pubsub.Broker

	interval int64
}

// GetEpoch returns the current epoch and the number of seconds since the
// begining of the current epoch.
func (s *SystemTimeSource) GetEpoch() (epoch EpochTime, elasped uint64) {
	return getEpochAt(time.Now(), s.interval)
}

// WatchEpochs returns a channel that produces a stream of messages on epoch
// transitions.
func (s *SystemTimeSource) WatchEpochs() <-chan EpochTime {
	return subscribeTyped(s.notifier)
}

func (s *SystemTimeSource) worker() {
	t := time.NewTicker(1 * time.Second)
	epoch, _ := s.GetEpoch()
	for {
		<-t.C
		if newEpoch, _ := s.GetEpoch(); newEpoch != epoch {
			s.logger.Debug("epoch transition",
				"prev_epoch", epoch,
				"epoch", newEpoch,
			)
			s.notifier.Broadcast(newEpoch)
			epoch = newEpoch
		}
	}
}

// NewSystemTimeSource constructs a new SystemTimeSource instance, with
// the specified epoch interval.
func NewSystemTimeSource(interval int64) TimeSource {
	if interval <= 0 {
		panic("epochtime: invalid epoch interval")
	}

	s := &SystemTimeSource{
		logger:   logging.GetLogger("SystemTimeSource"),
		notifier: pubsub.NewBroker(false),
		interval: interval,
	}

	if interval != EpochInterval {
		s.logger.Debug("non-standard epoch interval",
			"interval", interval,
		)
	}

	go s.worker()

	return s
}

// MockTimeSource is a mock time source that is driven manually
// via calls to a function.
type MockTimeSource struct {
	sync.Mutex

	logger   *logging.Logger
	notifier *pubsub.Broker

	epoch   EpochTime
	elapsed uint64
}

// GetEpoch returns the current epoch and the number of seconds since the
// begining of the current epoch.
func (s *MockTimeSource) GetEpoch() (epoch EpochTime, elapsed uint64) {
	s.Lock()
	defer s.Unlock()

	epoch, elapsed = s.epoch, s.elapsed
	return
}

// WatchEpochs returns a channel that produces a stream of messages on epoch
// transitions.
func (s *MockTimeSource) WatchEpochs() <-chan EpochTime {
	return subscribeTyped(s.notifier)
}

// SetEpoch sets the mock epoch and offset.
func (s *MockTimeSource) SetEpoch(epoch EpochTime, elapsed uint64) {
	s.Lock()
	defer s.Unlock()

	if elapsed > EpochInterval {
		panic("mocktime: elapsed time greater than EpochInterval")
	}
	oldEpoch := s.epoch
	s.epoch, s.elapsed = epoch, elapsed
	if oldEpoch != epoch {
		s.logger.Debug("epoch transition",
			"prev_epoch", oldEpoch,
			"epoch", epoch,
		)
		s.notifier.Broadcast(epoch)
	}
}

// NewMockTimeSource constructs a new MockTimeSource instance.
func NewMockTimeSource() *MockTimeSource {
	return &MockTimeSource{
		logger:   logging.GetLogger("MockTimeSource"),
		notifier: pubsub.NewBroker(false),
	}
}

func getEpochAt(at time.Time, interval int64) (epoch EpochTime, elapsed uint64) {
	delta := int64(at.Sub(ekidenEpochBase).Seconds())
	if delta < 0 {
		panic("epochtime: time predates EkidenEpoch")
	}

	epoch = EpochTime(delta / interval)
	elapsed = uint64(delta % interval)
	return
}

func subscribeTyped(notifier *pubsub.Broker) <-chan EpochTime {
	rawCh := notifier.Subscribe()
	typedCh := make(chan EpochTime)

	go func() {
		for {
			epoch, ok := <-rawCh
			if !ok {
				close(typedCh)
				return
			}
			typedCh <- epoch.(EpochTime)
		}
	}()

	return typedCh
}
