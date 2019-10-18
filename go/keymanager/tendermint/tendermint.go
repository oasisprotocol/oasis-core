// Package tendermint provides the tendermint backed key manager management
// implementation.
package tendermint

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
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/tendermint/apps/keymanager"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// BackendName is the name of the backend.
const BackendName = tmapi.BackendName

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	notifier *pubsub.Broker
}

func (r *tendermintBackend) GetStatus(ctx context.Context, id signature.PublicKey) (*api.Status, error) {
	q, err := r.querier.QueryAt(0)
	if err != nil {
		return nil, err
	}

	return q.Status(ctx, id)
}

func (r *tendermintBackend) GetStatuses(ctx context.Context) ([]*api.Status, error) {
	q, err := r.querier.QueryAt(0)
	if err != nil {
		return nil, err
	}

	return q.Statuses(ctx)
}

func (r *tendermintBackend) WatchStatuses() (<-chan *api.Status, *pubsub.Subscription) {
	sub := r.notifier.Subscribe()
	ch := make(chan *api.Status)
	sub.Unwrap(ch)

	return ch, sub
}

func (r *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := r.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (r *tendermintBackend) worker(ctx context.Context) {
	sub, err := r.service.Subscribe("keymanager-worker", app.QueryApp)
	if err != nil {
		r.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer r.service.Unsubscribe("keymanager-worker", app.QueryApp) // nolint: errcheck

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
			r.onEventDataNewBlock(ev)
		default:
		}
	}
}

func (r *tendermintBackend) onEventDataNewBlock(ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()
	events = append(events, ev.ResultEndBlock.GetEvents()...)

	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeOasis {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagStatusUpdate) {
				var statuses []*api.Status
				if err := cbor.Unmarshal(pair.GetValue(), &statuses); err != nil {
					r.logger.Error("worker: failed to get statuses from tag",
						"err", err,
					)
					continue
				}

				for _, status := range statuses {
					r.notifier.Broadcast(status)
				}
			}
		}
	}
}

// New constructs a new tendermint backed key manager management Backend
// instance.
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService) (api.Backend, error) {
	a := app.New(timeSource)
	if err := service.RegisterApplication(a); err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: failed to register app")
	}

	r := &tendermintBackend{
		logger:  logging.GetLogger("keymanager/tendermint"),
		service: service,
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	r.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		statuses, err := r.GetStatuses(ctx)
		if err != nil {
			r.logger.Error("status notifier: unable to get a list of statuses",
				"err", err,
			)
			return
		}

		wr := ch.In()
		for _, v := range statuses {
			wr <- v
		}
	})
	go r.worker(ctx)

	return r, nil
}
