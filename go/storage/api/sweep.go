package api

import (
	"sync"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

// SweepableBackend is a Backend capable of being cleaned by a Sweeper.
type SweepableBackend interface {
	Backend

	// PurgeExpired purges keys that expire before the provided epoch.
	PurgeExpired(epochtime.EpochTime)
}

// Sweeper is a generic storage sweeper that removes expired storage
// entries.
type Sweeper struct {
	sync.Once

	backend SweepableBackend

	closeCh  chan interface{}
	closedCh chan interface{}
}

// Close terminates the Sweeper worker.
func (s *Sweeper) Close() {
	s.Do(func() {
		close(s.closeCh)
		<-s.closedCh
	})
}

func (s *Sweeper) worker(timeSource epochtime.Backend) {
	defer close(s.closedCh)

	epochCh, sub := timeSource.WatchEpochs()
	defer sub.Close()

	epoch := epochtime.EpochInvalid
	for {
		select {
		case <-s.closeCh:
			return
		case newEpoch, ok := <-epochCh:
			if !ok {
				return
			}
			if epoch == newEpoch {
				continue
			}
			epoch = newEpoch
		}

		s.backend.PurgeExpired(epoch)
	}
}

// NewSweeper constructs a new Sweeper for the provided Backend.
func NewSweeper(backend SweepableBackend, timeSource epochtime.Backend) *Sweeper {
	s := &Sweeper{
		backend:  backend,
		closeCh:  make(chan interface{}),
		closedCh: make(chan interface{}),
	}

	go s.worker(timeSource)

	return s
}
