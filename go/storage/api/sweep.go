package api

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

var (
	sweepLatency = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_purge_expired_latency",
			Help: "Storage purge_expired latency (sec).",
		},
	)
	sweepCalls = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_purge_expired_calls",
			Help: "Number of storage purge_expired calls.",
		},
	)

	sweepCollectors = []prometheus.Collector{
		sweepLatency,
		sweepCalls,
	}

	sweepMetricsOnce sync.Once
)

// SweepableBackend is a Backend capable of being cleaned by a Sweeper.
type SweepableBackend interface {
	Backend

	// PurgeExpired purges keys that expire before the provided epoch.
	PurgeExpired(epochtime.EpochTime)
}

// Sweeper is a generic storage sweeper that removes expired storage
// entries.
type Sweeper struct { // nolint: maligned
	sync.Once
	sync.Mutex

	backend SweepableBackend

	closeCh  chan struct{}
	closedCh chan struct{}
	initCh   chan struct{}

	epoch        epochtime.EpochTime
	signaledInit bool
}

// GetEpoch returns the sweeper's idea of the current epoch.
func (s *Sweeper) GetEpoch() epochtime.EpochTime {
	s.Lock()
	defer s.Unlock()

	return s.epoch
}

// Close terminates the Sweeper worker.
func (s *Sweeper) Close() {
	s.Do(func() {
		close(s.closeCh)
		<-s.closedCh
	})
}

// Initialized returns a channel that will be closed when the sweeper
// is fully initialized.
func (s *Sweeper) Initialized() <-chan struct{} {
	return s.initCh
}

func (s *Sweeper) worker(timeSource epochtime.Backend) {
	defer close(s.closedCh)

	epochCh, sub := timeSource.WatchEpochs()
	defer sub.Close()

	for {
		select {
		case <-s.closeCh:
			return
		case newEpoch, ok := <-epochCh:
			if !ok {
				return
			}
			if !s.signaledInit {
				s.signaledInit = true
				close(s.initCh)
			}
			if s.epoch == newEpoch {
				continue
			}
			s.Lock()
			s.epoch = newEpoch
			s.Unlock()
		}

		start := time.Now()
		s.backend.PurgeExpired(s.epoch)
		sweepLatency.Observe(time.Since(start).Seconds())
		sweepCalls.Inc()
	}
}

// NewSweeper constructs a new Sweeper for the provided Backend.
func NewSweeper(backend SweepableBackend, timeSource epochtime.Backend) *Sweeper {
	sweepMetricsOnce.Do(func() {
		prometheus.MustRegister(sweepCollectors...)
	})

	s := &Sweeper{
		backend:  backend,
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
		initCh:   make(chan struct{}),
		epoch:    epochtime.EpochInvalid,
	}

	go s.worker(timeSource)

	return s
}
