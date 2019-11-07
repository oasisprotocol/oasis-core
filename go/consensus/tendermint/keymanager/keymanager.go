// Package keymanager provides the tendermint backed key manager management
// implementation.
package keymanager

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	tmapi "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/keymanager"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
)

// BackendName is the name of the backend.
const BackendName = tmapi.BackendName

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	notifier *pubsub.Broker
}

func (tb *tendermintBackend) GetStatus(ctx context.Context, id signature.PublicKey, height int64) (*api.Status, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Status(ctx, id)
}

func (tb *tendermintBackend) GetStatuses(ctx context.Context, height int64) ([]*api.Status, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Statuses(ctx)
}

func (tb *tendermintBackend) WatchStatuses() (<-chan *api.Status, *pubsub.Subscription) {
	sub := tb.notifier.Subscribe()
	ch := make(chan *api.Status)
	sub.Unwrap(ch)

	return ch, sub
}

func (tb *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (tb *tendermintBackend) worker(ctx context.Context) {
	sub, err := tb.service.Subscribe("keymanager-worker", app.QueryApp)
	if err != nil {
		tb.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer tb.service.Unsubscribe("keymanager-worker", app.QueryApp) // nolint: errcheck

	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tb.onEventDataNewBlock(ev)
		default:
		}
	}
}

func (tb *tendermintBackend) onEventDataNewBlock(ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()
	events = append(events, ev.ResultEndBlock.GetEvents()...)

	for _, tmEv := range events {
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.KeyStatusUpdate) {
				var statuses []*api.Status
				if err := cbor.Unmarshal(pair.GetValue(), &statuses); err != nil {
					tb.logger.Error("worker: failed to get statuses from tag",
						"err", err,
					)
					continue
				}

				for _, status := range statuses {
					tb.notifier.Broadcast(status)
				}
			}
		}
	}
}

// New constructs a new tendermint backed key manager management Backend
// instance.
func New(ctx context.Context, service service.TendermintService) (api.Backend, error) {
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: failed to register app")
	}

	tb := &tendermintBackend{
		logger:  logging.GetLogger("keymanager/tendermint"),
		service: service,
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	tb.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		statuses, err := tb.GetStatuses(ctx, 0)
		if err != nil {
			tb.logger.Error("status notifier: unable to get a list of statuses",
				"err", err,
			)
			return
		}

		wr := ch.In()
		for _, v := range statuses {
			wr <- v
		}
	})
	go tb.worker(ctx)

	return tb, nil
}
