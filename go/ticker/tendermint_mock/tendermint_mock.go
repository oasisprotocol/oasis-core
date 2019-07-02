// Package tendermintmock implements the mock (settable) tendermint backed epochtime backend.
package tendermintmock

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"math/rand"
	"sync"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/ticker_mock"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/ticker/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "tendermint_mock"
)

var _ api.Backend = (*tendermintMockBackend)(nil)

type tendermintMockBackend struct {
	sync.RWMutex

	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker

	tick api.TickTime
}

func (t *tendermintMockBackend) GetTick(ctx context.Context, height int64, multiplier uint64) (api.TickTime, error) {
	response, err := t.service.Query(app.QueryGetTick, nil, height)
	if err != nil {
		return 0, errors.Wrap(err, "ticker: get block epoch query failed")
	}

	var data app.QueryGetTickResponse
	if err := cbor.Unmarshal(response, &data); err != nil {
		return 0, errors.Wrap(err, "ticker: get block epoch malformed response")
	}

	return api.TickTime(uint64(data.Tick) / multiplier), nil
}

func (t *tendermintMockBackend) WatchTicks(multiplier uint64) (<-chan api.TickTime, *pubsub.Subscription) {
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

func nonce() uint64 {
	rng := rand.New(mathrand.New(cryptorand.Reader))
	return rng.Uint64()
}

func (t *tendermintMockBackend) DoTick(ctx context.Context) error {
	tx := app.Tx{
		TxDoTick: &app.TxDoTick{Nonce: nonce()},
	}
	tick := t.tick
	ch, sub := t.WatchTicks(1)
	defer sub.Close()

	if err := t.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "ticker: do tick failed")
	}
	for {
		select {
		case newTick, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if newTick > tick {
				return nil
			}
		case <-ctx.Done():
			return context.Canceled
		}
	}
}

func (t *tendermintMockBackend) worker(ctx context.Context) {
	// Subscribe to blocks which advance the epoch.
	sub, err := t.service.Subscribe("ticker-worker", app.QueryApp)
	if err != nil {
		t.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer t.service.Unsubscribe("ticker-worker", app.QueryApp) // nolint: errcheck

	// Populate current tick (if available).
	response, err := t.service.Query(app.QueryGetTick, nil, 0)
	if err == nil {
		var data app.QueryGetTickResponse
		if err := cbor.Unmarshal(response, &data); err != nil {
			panic("worker: malformed current epoch response")
		}

		t.Lock()
		t.tick = data.Tick
		t.notifier.Broadcast(t.tick)
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
	events := ev.ResultBeginBlock.GetEvents()

	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeEkiden {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagTick) {
				var tick api.TickTime
				if err := cbor.Unmarshal(pair.GetValue(), &tick); err != nil {
					t.logger.Error("worker: malformed mock tick",
						"err", err,
					)
					continue
				}
				t.Lock()
				t.tick = tick
				t.notifier.Broadcast(t.tick)
				t.Unlock()
			}
		}
	}
}

// New constructs a new mock tendermint backed epochtime Backend instance.
func New(ctx context.Context, service service.TendermintService) (api.SetableBackend, error) {
	// Initialze and register the tendermint service component.
	app := app.New()
	if err := service.RegisterApplication(app, nil); err != nil {
		return nil, err
	}

	t := &tendermintMockBackend{
		logger:  logging.GetLogger("ticker/tendermint_mock"),
		service: service,
	}
	t.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		t.RLock()
		defer t.RUnlock()

		ch.In() <- t.tick
	})

	go t.worker(ctx)

	return t, nil
}
