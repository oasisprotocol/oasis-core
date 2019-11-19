// Package epochtime implements the tendermint backed epochtime backend.
package epochtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
)

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	sync.RWMutex

	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker

	interval     int64
	lastNotified api.EpochTime
	epoch        api.EpochTime
	base         api.EpochTime
}

func (t *tendermintBackend) GetBaseEpoch(context.Context) (api.EpochTime, error) {
	return t.base, nil
}

func (t *tendermintBackend) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	if height == 0 {
		t.RLock()
		defer t.RUnlock()
		return t.epoch, nil
	}
	epoch := t.base + api.EpochTime(height/t.interval)

	return epoch, nil
}

func (t *tendermintBackend) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	if epoch < t.base {
		return 0, fmt.Errorf("epochtime/tendermint: epoch predates base")
	}
	height := int64(epoch-t.base) * t.interval

	return height, nil
}

func (t *tendermintBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	now, err := t.GetEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	return &api.Genesis{
		Parameters: api.ConsensusParameters{
			DebugMockBackend: false,
			Interval:         t.interval,
		},
		Base: now,
	}, nil
}

func (t *tendermintBackend) worker(ctx context.Context) {
	ch, sub := t.service.WatchBlocks()
	defer sub.Close()

	for {
		block, ok := <-ch
		if !ok {
			return
		}

		if t.updateCached(ctx, block) {
			// Safe to look at `t.epoch`, only mutator is the line above.
			t.notifier.Broadcast(t.epoch)
		}
	}
}

func (t *tendermintBackend) updateCached(ctx context.Context, block *tmtypes.Block) bool {
	t.Lock()
	defer t.Unlock()

	epoch, _ := t.GetEpoch(ctx, block.Header.Height)

	t.epoch = epoch

	if t.lastNotified != epoch {
		t.logger.Debug("epoch transition",
			"prev_epoch", t.lastNotified,
			"epoch", epoch,
		)
		t.lastNotified = t.epoch
		return true
	}
	return false
}

// New constructs a new tendermint backed epochtime Backend instance,
// with the specified epoch interval.
func New(ctx context.Context, service service.TendermintService, interval int64) (api.Backend, error) {
	base := service.GetGenesis().EpochTime.Base
	r := &tendermintBackend{
		logger:   logging.GetLogger("epochtime/tendermint"),
		service:  service,
		interval: interval,
		base:     base,
		epoch:    base,
	}
	r.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		r.RLock()
		defer r.RUnlock()

		if r.lastNotified == r.epoch {
			ch.In() <- r.epoch
		}
	})

	go r.worker(ctx)

	return r, nil
}
