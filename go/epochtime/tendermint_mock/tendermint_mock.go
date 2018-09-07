// Package tendermint implements the mock (settable) tendermint backed epochtime backend.
package tendermintmock

import (
	"sync"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	tmepochtime_mock "github.com/oasislabs/ekiden/go/tendermint/apps/epochtime_mock"
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

func (t *tendermintMockBackend) GetEpoch(ctx context.Context) (api.EpochTime, uint64, error) {
	t.RLock()
	defer t.RUnlock()

	return t.epoch, 0, nil
}

func (t *tendermintMockBackend) GetBlockEpoch(ctx context.Context, height int64) (api.EpochTime, uint64, error) {
	response, err := t.service.Query(tmapi.QueryEpochTimeMockGetEpoch, tmapi.QueryGetEpoch{}, height)
	if err != nil {
		return 0, 0, errors.Wrap(err, "epochtime: get block epoch query failed")
	}

	var data tmapi.QueryGetEpochResponse
	if err := cbor.Unmarshal(response, &data); err != nil {
		return 0, 0, errors.Wrap(err, "epochtime: get block epoch malformed response")
	}

	return data.Epoch, 0, nil
}

func (t *tendermintMockBackend) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	t.RLock()
	defer t.RUnlock()

	if epoch == t.epoch {
		return t.currentBlock, nil
	}

	return 0, errors.New("epochtime: not implemented for historic epochs")
}

func (t *tendermintMockBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintMockBackend) SetEpoch(ctx context.Context, epoch api.EpochTime, elapsed uint64) error {
	tx := tmapi.TxEpochTimeMock{
		TxSetEpoch: &tmapi.TxSetEpoch{
			Epoch: epoch,
		},
	}

	if err := t.service.BroadcastTx(tmapi.EpochTimeMockTransactionTag, tx); err != nil {
		return errors.Wrap(err, "epochtime: set epoch failed")
	}

	return nil
}

func (t *tendermintMockBackend) worker() {
	// Subscribe to transactions which advance the epoch.
	ctx := context.Background()
	txChannel := make(chan interface{})

	if err := t.service.Subscribe(ctx, "epochtime-worker", tmapi.QueryEpochTimeMockApp, txChannel); err != nil {
		panic("worker: failed to subscribe")
	}
	defer t.service.Unsubscribe(ctx, "epochtime-worker", tmapi.QueryEpochTimeMockApp) // nolint: errcheck

	// Populate current epoch (if available).
	response, err := t.service.Query(tmapi.QueryEpochTimeMockGetEpoch, tmapi.QueryGetEpoch{}, 0)
	if err == nil {
		var data tmapi.QueryGetEpochResponse
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
		event, ok := <-txChannel
		if !ok {
			t.logger.Debug("worker: terminating")
			return
		}

		ev := event.(tmtypes.EventDataTx)
		rawEpoch := tmapi.GetTag(ev.Result.GetTags(), tmapi.TagEpochTimeMockEpoch)
		if rawEpoch == nil {
			t.logger.Error("worker: missing epoch tag in transaction")
			continue
		}

		var epoch api.EpochTime
		if err := cbor.Unmarshal(rawEpoch, &epoch); err != nil {
			t.logger.Error("worker: malformed epoch tag in transaction")
			continue
		}

		if t.updateCached(ev.Height, epoch) {
			// Safe to look at `t.epoch`, only mutator is the line above.
			t.notifier.Broadcast(t.epoch)
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
		)
		t.lastNotified = t.epoch
		return true
	}
	return false
}

// New constructs a new mock tendermint backed epochtime Backend instance.
func New(service service.TendermintService) (api.SetableBackend, error) {
	// Initialze and register the tendermint service component.
	app := tmepochtime_mock.New()
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

	go r.worker()

	return r, nil
}
