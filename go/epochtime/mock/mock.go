// Package mock implements the mock (setable) epochtime backend.
package mock

import (
	"sync"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
)

// BackendName is the name of this implementation.
const BackendName = "mock"

var (
	_ (api.Backend)        = (*mockBackend)(nil)
	_ (api.SetableBackend) = (*mockBackend)(nil)
)

type mockBackend struct {
	sync.Mutex

	logger   *logging.Logger
	notifier *pubsub.Broker

	lastNotified api.EpochTime
	epoch        api.EpochTime
}

func (m *mockBackend) GetEpoch(ctx context.Context) (api.EpochTime, error) {
	m.Lock()
	defer m.Unlock()

	return m.epoch, nil
}

func (m *mockBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := m.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (m *mockBackend) SetEpoch(ctx context.Context, epoch api.EpochTime) error {
	if m.updateEpoch(epoch) {
		m.notifier.Broadcast(epoch)
	}

	return nil
}

func (m *mockBackend) updateEpoch(epoch api.EpochTime) bool {
	m.Lock()
	defer m.Unlock()

	oldEpoch := m.epoch
	m.epoch = epoch

	if oldEpoch != epoch {
		m.lastNotified = epoch
		m.logger.Debug("epoch transition",
			"prev_epoch", oldEpoch,
			"epoch", epoch,
		)
		return true
	}

	return false
}

// New constructs a new mock (user-driven) epochtime Backend instance.
func New() api.SetableBackend {
	s := &mockBackend{
		logger: logging.GetLogger("epochtime/mock"),
	}
	s.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		s.Lock()
		defer s.Unlock()

		// Iff the notifications for the current epoch went out,
		// broadcast the current epoch on subscribe, otherwise,
		// assume that the event mechanism will handle it.
		if s.epoch == s.lastNotified {
			ch.In() <- s.epoch
		}
	})

	s.logger.Debug("initialized",
		"backend", BackendName,
	)

	return s
}
