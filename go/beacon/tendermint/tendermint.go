// Package tendermint implementes the tendermint backed beacon backend.
package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/beacon"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

var _ api.Backend = (*Backend)(nil)

// Backend is a tendermint backed random beacon.
type Backend struct {
	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker
}

func (t *Backend) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	resp, err := t.service.Query(app.QueryGetBeacon, nil, height)
	if err != nil {
		return nil, errors.Wrap(err, "beacon: failed to query beacon")
	}

	return resp, nil
}

func (t *Backend) WatchBeacons() (<-chan *api.GenerateEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.GenerateEvent)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *Backend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()

	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeEkiden {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagGenerated) {
				var genEv api.GenerateEvent
				if err := cbor.Unmarshal(pair.GetValue(), &genEv); err != nil {
					t.logger.Error("worker: failed to get beacon event from tag",
						"err", err,
					)
					continue
				}

				t.logger.Debug("worker: got new beacon",
					"beacon", hex.EncodeToString(genEv.Beacon),
				)

				t.notifier.Broadcast(&genEv)
			}
		}
	}
}

func (t *Backend) worker(ctx context.Context) {
	sub, err := t.service.Subscribe("beacon-worker", app.QueryApp)
	if err != nil {
		t.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer t.service.Unsubscribe("beacon-worker", app.QueryApp) // nolint: errcheck

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

// New constructs a new tendermint backed beacon Backend instance.
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService, debugDeterministic bool) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	// Initialize and register the tendermint service component.
	app := app.New(timeSource, debugDeterministic)
	if err := service.RegisterApplication(app, nil); err != nil {
		return nil, err
	}

	t := &Backend{
		logger:   logging.GetLogger("beacon/tendermint"),
		service:  service,
		notifier: pubsub.NewBroker(true),
	}

	go t.worker(ctx)

	return t, nil
}
