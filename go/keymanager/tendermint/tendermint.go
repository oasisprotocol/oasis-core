// Package tendermint provides the tendermint backed key manager management
// implementation.
package tendermint

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/keymanager"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of the backend.
const BackendName = "tendermint"

type tendermintBackend struct {
	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker
}

func (r *tendermintBackend) GetStatus(ctx context.Context, id signature.PublicKey) (*api.Status, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := r.service.Query(app.QueryGetStatus, query, 0)
	if err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: get status query failed")
	}
	if response == nil {
		return nil, api.ErrNoSuchKeyManager
	}

	var status api.Status
	if err = cbor.Unmarshal(response, &status); err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: get status malformed response")
	}

	return &status, nil
}

func (r *tendermintBackend) GetStatuses(ctx context.Context) ([]*api.Status, error) {
	response, err := r.service.Query(app.QueryGetStatuses, nil, 0)
	if err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: get statuses query failed")
	}

	var statuses []*api.Status
	if err = cbor.Unmarshal(response, &statuses); err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: get statuses malformed response")
	}

	return statuses, nil
}

func (r *tendermintBackend) WatchStatuses() (<-chan *api.Status, *pubsub.Subscription) {
	sub := r.notifier.Subscribe()
	ch := make(chan *api.Status)
	sub.Unwrap(ch)

	return ch, sub
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
		if tmEv.GetType() != tmapi.EventTypeEkiden {
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
	// We can only work with a block-based epochtime.
	blockTimeSource, ok := timeSource.(epochtime.BlockBackend)
	if !ok {
		return nil, errors.New("keymanager/tendermint: need a block-based epochtime backend")
	}

	app := app.New(blockTimeSource)
	if err := service.RegisterApplication(app); err != nil {
		return nil, errors.Wrap(err, "keymanager/tendermint: failed to register app")
	}

	r := &tendermintBackend{
		logger:  logging.GetLogger("keymanager/tendermint"),
		service: service,
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
