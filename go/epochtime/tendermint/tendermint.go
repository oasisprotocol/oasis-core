// Package tendermint implements the tendermint backed epochtime backend.
package tendermint

import (
	"sync"

	"github.com/eapache/channels"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "tendermint"
)

var (
	_ api.BlockBackend = (*tendermintBackend)(nil)
)

type tendermintBackend struct {
	sync.RWMutex

	logger *logging.Logger

	client   tmcli.Client
	notifier *pubsub.Broker

	interval int64

	cached struct {
		epoch   api.EpochTime
		elapsed uint64
	}
}

func (t *tendermintBackend) GetEpoch(ctx context.Context) (api.EpochTime, uint64, error) {
	t.RLock()
	defer t.RUnlock()

	return t.cached.epoch, t.cached.elapsed, nil
}

func (t *tendermintBackend) GetBlockEpoch(ctx context.Context, height int64) (api.EpochTime, uint64, error) {
	epoch := api.EpochTime(height / t.interval)
	elapsed := uint64(height % t.interval)

	return epoch, elapsed, nil
}

func (t *tendermintBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintBackend) worker() {
	blockCh := make(chan interface{})
	if err := t.client.Subscribe(context.Background(), "epochtime/tendermint", tmtypes.EventQueryNewBlock, blockCh); err != nil {
		t.logger.Error("worker: failed to subscribe to new block events",
			"err", err,
		)
		return
	}

	for {
		v, ok := <-blockCh
		if !ok {
			return
		}

		ev := v.(tmtypes.EventDataNewBlock)
		t.updateCached(ev.Block)
	}
}

func (t *tendermintBackend) updateCached(block *tmtypes.Block) {
	lastNotified := t.cached.epoch
	epoch, elapsed, _ := t.GetBlockEpoch(context.Background(), block.Header.Height)
	changed := epoch != lastNotified

	t.Lock()
	t.cached.epoch = epoch
	t.cached.elapsed = elapsed
	t.Unlock()

	if changed {
		t.logger.Debug("epoch transition",
			"prev_epoch", lastNotified,
			"epoch", epoch,
		)
		t.notifier.Broadcast(epoch)
	}
}

// New constructs a new tendermint backed epochtime Backend instance,
// with the specified epoch interval.
func New(service service.TendermintService, interval int64) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	r := &tendermintBackend{
		logger:   logging.GetLogger("epochtime/tendermint"),
		client:   service.GetClient(),
		interval: interval,
	}
	r.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		epoch, _, err := r.GetEpoch(context.Background())
		if err != nil {
			panic(err)
		}

		ch.In() <- epoch
	})

	go r.worker()

	return r, nil
}
