// Package tendermint implements the mock (settable) tendermint backed epochtime backend.
package tendermintmock

import (
	"bytes"
	"context"
	"sync"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/epochtime_mock"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "tendermint_mock"
)

var _ api.BlockBackend = (*tendermintMockBackend)(nil)

type tendermintMockBackend struct {
	sync.RWMutex

	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker

	lastNotified api.EpochTime
	epoch        api.EpochTime
	currentBlock int64
}

func (t *tendermintMockBackend) GetEpoch(ctx context.Context) (api.EpochTime, error) {
	t.RLock()
	defer t.RUnlock()

	return t.epoch, nil
}

func (t *tendermintMockBackend) GetBlockEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	response, err := t.service.Query(app.QueryGetEpoch, nil, height)
	if err != nil {
		return 0, errors.Wrap(err, "epochtime: get block epoch query failed")
	}

	var data app.QueryGetEpochResponse
	if err := cbor.Unmarshal(response, &data); err != nil {
		return 0, errors.Wrap(err, "epochtime: get block epoch malformed response")
	}

	return data.Epoch, nil
}

func (t *tendermintMockBackend) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	t.RLock()
	defer t.RUnlock()

	if epoch == t.epoch {
		return t.currentBlock, nil
	}

	t.logger.Error("epochtime: attempted to get block for historic epoch",
		"epoch", epoch,
		"current_epoch", t.epoch,
	)

	return 0, errors.New("epochtime: not implemented for historic epochs")
}

func (t *tendermintMockBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintMockBackend) SetEpoch(ctx context.Context, epoch api.EpochTime) error {
	tx := app.Tx{
		TxSetEpoch: &app.TxSetEpoch{
			Epoch: epoch,
		},
	}

	ch, sub := t.WatchEpochs()
	defer sub.Close()

	if err := t.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "epochtime: set epoch failed")
	}

	for {
		select {
		case newEpoch, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if newEpoch == epoch {
				return nil
			}
		case <-ctx.Done():
			return context.Canceled
		}
	}
}

func (t *tendermintMockBackend) worker(ctx context.Context) {
	// Subscribe to transactions which advance the epoch.
	sub, err := t.service.Subscribe("epochtime-worker", app.QueryApp)
	if err != nil {
		t.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer t.service.Unsubscribe("epochtime-worker", app.QueryApp) // nolint: errcheck

	// Populate current epoch (if available).
	response, err := t.service.Query(app.QueryGetEpoch, nil, 0)
	if err == nil {
		var data app.QueryGetEpochResponse
		if err := cbor.Unmarshal(response, &data); err != nil {
			panic("worker: malformed current epoch response")
		}

		t.Lock()
		t.epoch = data.Epoch
		t.currentBlock = data.Height
		t.notifier.Broadcast(t.epoch)
		t.Unlock()
	}

	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			t.logger.Debug("worker: terminating, subscription closed")
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			t.onEventDataNewBlock(ctx, ev)
		default:
		}
	}
}

func (t *tendermintMockBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	tags := ev.ResultBeginBlock.GetTags()

	for _, pair := range tags {
		if bytes.Equal(pair.GetKey(), app.TagEpoch) {
			var epoch api.EpochTime
			if err := cbor.Unmarshal(pair.GetValue(), &epoch); err != nil {
				t.logger.Error("worker: malformed mock epoch",
					"err", err,
				)
				continue
			}

			if t.updateCached(ev.Block.Header.Height, epoch) {
				t.notifier.Broadcast(t.epoch)
			}
		}
	}
}

func (t *tendermintMockBackend) updateCached(height int64, epoch api.EpochTime) bool {
	t.Lock()
	defer t.Unlock()

	t.epoch = epoch
	t.currentBlock = height

	if t.lastNotified != epoch {
		t.logger.Debug("epoch transition",
			"prev_epoch", t.lastNotified,
			"epoch", epoch,
			"height", height,
		)
		t.lastNotified = t.epoch
		return true
	}
	return false
}

// New constructs a new mock tendermint backed epochtime Backend instance.
func New(ctx context.Context, service service.TendermintService) (api.SetableBackend, error) {
	// Initialze and register the tendermint service component.
	app := app.New()
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	r := &tendermintMockBackend{
		logger:  logging.GetLogger("epochtime/tendermint_mock"),
		service: service,
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
