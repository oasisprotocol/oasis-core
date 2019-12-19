// Package scheduler implements the tendermint backed scheduling backend.
package scheduler

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/scheduler/api"
)

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	notifier *pubsub.Broker
}

func (tb *tendermintBackend) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, errors.Wrap(err, "scheduler: genesis query failed")
	}
	return q.Genesis(ctx)
}

func (tb *tendermintBackend) Cleanup() {
}

func (tb *tendermintBackend) GetValidators(ctx context.Context, height int64) ([]*api.Validator, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Validators(ctx)
}

func (tb *tendermintBackend) GetCommittees(ctx context.Context, request *api.GetCommitteesRequest) ([]*api.Committee, error) {
	q, err := tb.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	committees, err := q.AllCommittees(ctx)
	if err != nil {
		return nil, err
	}

	var runtimeCommittees []*api.Committee
	for _, c := range committees {
		if c.RuntimeID.Equal(request.RuntimeID) {
			runtimeCommittees = append(runtimeCommittees, c)
		}
	}

	return runtimeCommittees, nil
}

func (tb *tendermintBackend) WatchCommittees(ctx context.Context) (<-chan *api.Committee, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Committee)
	sub := tb.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) getCurrentCommittees() ([]*api.Committee, error) {
	q, err := tb.querier.QueryAt(context.TODO(), consensus.HeightLatest)
	if err != nil {
		return nil, err
	}

	return q.AllCommittees(context.TODO())
}

func (tb *tendermintBackend) worker(ctx context.Context) {
	// Subscribe to blocks which elect committees.
	sub, err := tb.service.Subscribe("scheduler-worker", app.QueryApp)
	if err != nil {
		tb.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer func() {
		err := tb.service.Unsubscribe("scheduler-worker", app.QueryApp)
		if err != nil {
			tb.logger.Error("failed to unsubscribe",
				"err", err,
			)
		}
	}()

	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			tb.logger.Debug("worker: terminating, subscription closed")
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tb.onEventDataNewBlock(ctx, ev)
		default:
		}
	}
}

// Called from worker.
func (tb *tendermintBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()

	for _, tmEv := range events {
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.KeyElected) {
				var kinds []api.CommitteeKind
				if err := cbor.Unmarshal(pair.GetValue(), &kinds); err != nil {
					tb.logger.Error("worker: malformed elected committee types list",
						"err", err,
					)
					continue
				}

				q, err := tb.querier.QueryAt(ctx, ev.Block.Header.Height)
				if err != nil {
					tb.logger.Error("worker: couldn't query elected committees",
						"err", err,
					)
					continue
				}

				committees, err := q.KindsCommittees(ctx, kinds)
				if err != nil {
					tb.logger.Error("worker: couldn't query elected committees",
						"err", err,
					)
					continue
				}

				for _, c := range committees {
					tb.notifier.Broadcast(c)
				}
			}
		}
	}
}

// New constracts a new tendermint-based scheduler Backend instance.
func New(ctx context.Context, service service.TendermintService) (api.Backend, error) {
	// Initialze and register the tendermint service component.
	a, err := app.New()
	if err != nil {
		return nil, err
	}
	if err = service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		logger:  logging.GetLogger("scheduler/tendermint"),
		service: service,
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	tb.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		currentCommittees, err := tb.getCurrentCommittees()
		if err != nil {
			tb.logger.Error("couldn't get current committees. won't send them. good luck to the subscriber",
				"err", err,
			)
			return
		}
		for _, c := range currentCommittees {
			ch.In() <- c
		}
	})

	go tb.worker(ctx)

	return tb, nil
}
