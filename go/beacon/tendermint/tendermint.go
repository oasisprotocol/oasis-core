// Package tendermint implementes the tendermint backed beacon backend.
package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"

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
const BackendName = "tendermint"

var (
	_ api.Backend = (*Backend)(nil)

	errIncoherentTime = errors.New("beacon/tendermint: incoherent time")
)

// Backend is a tendermint backed random beacon.
type Backend struct {
	logger *logging.Logger

	timeSource epochtime.Backend
	service    service.TendermintService
	notifier   *pubsub.Broker

	cached struct {
		sync.RWMutex

		epoch  epochtime.EpochTime
		beacon []byte
	}
}

// GetBeacon gets the beacon for the provided block height.
// Calling this method with height `0`, should return the
// beacon for latest known block.
func (t *Backend) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	// Calling GetBlockEpoch with height `0` will return the epoch of the latest block.
	beaconEpoch, err := t.timeSource.GetBlockEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	if beacon := t.getCached(beaconEpoch); beacon != nil {
		return beacon, nil
	}

	resp, err := t.service.Query(app.QueryGetBeacon, nil, height)
	if err != nil {
		return nil, errors.Wrap(err, "beacon: failed to query beacon")
	}

	return resp, nil
}

// WatchBeacons returns a channel that produces a stream of api.GenerateEvent.
// Upon subscription, the most recently generate beacon will be sent
// immediately if available.
func (t *Backend) WatchBeacons() (<-chan *api.GenerateEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.GenerateEvent)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *Backend) getCached(epoch epochtime.EpochTime) []byte {
	t.cached.RLock()
	defer t.cached.RUnlock()

	if t.cached.epoch != epoch || t.cached.beacon == nil {
		return nil
	}

	return t.cached.beacon
}

func (t *Backend) setCached(ev *api.GenerateEvent) {
	t.cached.Lock()
	defer t.cached.Unlock()

	t.cached.epoch = ev.Epoch
	t.cached.beacon = append([]byte{}, ev.Beacon...)
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
					"epoch", genEv.Epoch,
					"beacon", hex.EncodeToString(genEv.Beacon),
				)

				t.setCached(&genEv)
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
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService) (api.Backend, error) {
	if err := service.ForceInitialize(); err != nil {
		return nil, err
	}

	// Initialize and register the tendermint service component.
	app := app.New(timeSource)
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	t := &Backend{
		logger:     logging.GetLogger("beacon/tendermint"),
		timeSource: timeSource,
		service:    service,
		notifier:   pubsub.NewBroker(true),
	}

	go t.worker(ctx)

	return t, nil
}
