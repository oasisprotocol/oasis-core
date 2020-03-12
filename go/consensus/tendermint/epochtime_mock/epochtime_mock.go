// Package epochtimemock implements the mock (settable) tendermint backed epochtime backend.
package epochtimemock

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/eapache/channels"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/epochtime_mock"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
)

var (
	testSigner signature.Signer

	_ api.Backend = (*tendermintMockBackend)(nil)
)

type tendermintMockBackend struct {
	sync.RWMutex

	logger *logging.Logger

	service  service.TendermintService
	querier  *app.QueryFactory
	notifier *pubsub.Broker

	lastNotified api.EpochTime
	epoch        api.EpochTime
	currentBlock int64
}

func (t *tendermintMockBackend) GetBaseEpoch(context.Context) (api.EpochTime, error) {
	return 0, nil
}

func (t *tendermintMockBackend) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	q, err := t.querier.QueryAt(ctx, height)
	if err != nil {
		return api.EpochInvalid, err
	}

	epoch, _, err := q.Epoch(ctx)
	return epoch, err
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

	return 0, fmt.Errorf("epochtime: not implemented for historic epochs")
}

func (t *tendermintMockBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	typedCh := make(chan api.EpochTime)
	sub := t.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (t *tendermintMockBackend) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	now, err := t.GetEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	return &api.Genesis{
		Parameters: api.ConsensusParameters{
			DebugMockBackend: true,
		},
		Base: now,
	}, nil
}

func (t *tendermintMockBackend) SetEpoch(ctx context.Context, epoch api.EpochTime) error {
	ch, sub := t.WatchEpochs()
	defer sub.Close()

	tx := transaction.NewTransaction(0, nil, app.MethodSetEpoch, epoch)
	if err := consensus.SignAndSubmitTx(ctx, t.service, testSigner, tx); err != nil {
		return fmt.Errorf("epochtime: set epoch failed: %w", err)
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
	// Subscribe to blocks which advance the epoch.
	sub, err := t.service.Subscribe("epochtime-worker", app.QueryApp)
	if err != nil {
		t.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer t.service.Unsubscribe("epochtime-worker", app.QueryApp) // nolint: errcheck

	// Populate current epoch (if available).
	q, err := t.querier.QueryAt(ctx, consensus.HeightLatest)
	if err == nil {
		var epoch api.EpochTime
		var height int64
		epoch, height, err = q.Epoch(ctx)
		if err != nil {
			t.logger.Error("failed to query epoch",
				"err", err,
			)
			return
		}

		t.Lock()
		t.epoch = epoch
		t.currentBlock = height
		t.notifier.Broadcast(t.epoch)
		t.Unlock()
	} else {
		t.logger.Warn("unable to query initial epoch",
			"err", err,
		)
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
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.KeyEpoch) {
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
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	r := &tendermintMockBackend{
		logger:  logging.GetLogger("epochtime/tendermint_mock"),
		service: service,
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	r.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		r.RLock()
		defer r.RUnlock()

		if r.lastNotified == r.epoch {
			ch.In() <- r.epoch
		}
	})

	if base := service.GetGenesis().EpochTime.Base; base != 0 {
		r.logger.Warn("ignoring non-zero base genesis epoch",
			"base", base,
		)
	}

	go r.worker(ctx)

	return r, nil
}

func init() {
	testSigner = memorySigner.NewTestSigner("oasis-core epochtime mock key seed")
}
