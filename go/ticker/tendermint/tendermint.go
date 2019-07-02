// Package tendermint implements the tendermint backed ticker backend.
package tendermint

import (
	"context"
	"sync"

	"github.com/eapache/channels"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/ticker/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = tmapi.BackendName
)

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	sync.RWMutex

	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker

	tickInterval int64

	tick api.TickTime
}

func (t *tendermintBackend) GetTick(ctx context.Context, height int64, multiplier uint64) (api.TickTime, error) {
	var tick api.TickTime
	if height == 0 {
		t.RLock()
		defer t.RUnlock()
		tick = t.tick
	} else {
		tick = api.TickTime(height / t.tickInterval)
	}
	tickTime := api.TickTime(uint64(tick) / multiplier)

	return tickTime, nil
}

func (t *tendermintBackend) WatchTicks(multiplier uint64) (<-chan api.TickTime, *pubsub.Subscription) {
	outCh := make(chan api.TickTime)
	typedCh := make(chan api.TickTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	go func() {
		defer close(outCh)

		var currentTick api.TickTime
		// Always start with sending current tick.
		t, ok := <-typedCh
		if !ok {
			return
		}
		currentTick = api.TickTime(uint64(t) / multiplier)
		outCh <- currentTick
		// Send on tick changes
		for {
			t, ok := <-typedCh
			if !ok {
				return
			}
			nextTick := api.TickTime(uint64(t) / multiplier)
			if nextTick != currentTick {
				outCh <- nextTick
				currentTick = nextTick
			}
		}
	}()

	return outCh, sub
}

func (t *tendermintBackend) worker(ctx context.Context) {
	ch, sub := t.service.WatchBlocks()
	defer sub.Close()

	for {
		block, ok := <-ch
		if !ok {
			return
		}

		t.updateTick(ctx, block)
	}
}

func (t *tendermintBackend) updateTick(ctx context.Context, block *tmtypes.Block) {
	t.Lock()
	defer t.Unlock()

	t.tick = api.TickTime(block.Header.Height / t.tickInterval)
	t.notifier.Broadcast(t.tick)
}

// New constructs a new tendermint backed ticker Backend instance,
// with the specified tick and epoch intervals.
func New(ctx context.Context, service service.TendermintService, tickInterval int64) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	r := &tendermintBackend{
		logger:       logging.GetLogger("ticker/tendermint"),
		service:      service,
		tickInterval: tickInterval,
	}
	r.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		r.RLock()
		defer r.RUnlock()

		ch.In() <- r.tick
	})

	go r.worker(ctx)

	return r, nil
}
