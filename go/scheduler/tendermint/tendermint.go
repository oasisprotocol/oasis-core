package tendermint

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/scheduler"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

var (
	_ api.Backend = (*tendermintScheduler)(nil)
)

type tendermintScheduler struct {
	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker
}

func (s *tendermintScheduler) Cleanup() {
}

func (s *tendermintScheduler) GetCommittees(ctx context.Context, id signature.PublicKey, height int64) ([]*api.Committee, error) {
	raw, err := s.service.Query(app.QueryAllCommittees, id, height)
	if err != nil {
		return nil, err
	}

	var committees []*api.Committee
	err = cbor.Unmarshal(raw, &committees)
	if err != nil {
		return nil, err
	}

	var runtimeCommittees []*api.Committee
	for _, c := range committees {
		if c.RuntimeID.Equal(id) {
			runtimeCommittees = append(runtimeCommittees, c)
		}
	}

	return runtimeCommittees, err
}

func (s *tendermintScheduler) WatchCommittees() (<-chan *api.Committee, *pubsub.Subscription) {
	typedCh := make(chan *api.Committee)
	sub := s.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (s *tendermintScheduler) getCurrentCommittees() ([]*api.Committee, error) {
	raw, err := s.service.Query(app.QueryAllCommittees, nil, 0)
	if err != nil {
		return nil, err
	}

	var committees []*api.Committee
	err = cbor.Unmarshal(raw, &committees)
	return committees, err
}

func (s *tendermintScheduler) worker(ctx context.Context) {
	// Subscribe to blocks which elect committees.
	sub, err := s.service.Subscribe("scheduler-worker", app.QueryApp)
	if err != nil {
		s.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer func() {
		err := s.service.Unsubscribe("scheduler-worker", app.QueryApp)
		if err != nil {
			s.logger.Error("failed to unsubscribe",
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
			s.logger.Debug("worker: terminating, subscription closed")
			return
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			s.onEventDataNewBlock(ctx, ev)
		default:
		}
	}
}

// Called from worker.
func (s *tendermintScheduler) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()

	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeEkiden {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagElected) {
				var kinds []api.CommitteeKind
				if err := cbor.Unmarshal(pair.GetValue(), &kinds); err != nil {
					s.logger.Error("worker: malformed elected committee types list",
						"err", err,
					)
					continue
				}

				raw, err := s.service.Query(app.QueryKindsCommittees, kinds, ev.Block.Header.Height)
				if err != nil {
					s.logger.Error("worker: couldn't query elected committees",
						"err", err,
					)
					continue
				}

				var committees []*api.Committee
				if err := cbor.Unmarshal(raw, &committees); err != nil {
					s.logger.Error("worker: malformed elected committees",
						"err", err,
					)
					continue
				}

				for _, c := range committees {
					s.notifier.Broadcast(c)
				}
			}
		}
	}
}

// New constracts a new tendermint-based scheduler Backend instance.
func New(ctx context.Context,
	timeSource epochtime.Backend,
	service service.TendermintService,
) (api.Backend, error) {
	// Initialze and register the tendermint service component.
	app := app.New(timeSource)
	if err := service.RegisterApplication(app, []string{registryapp.AppName}); err != nil {
		return nil, err
	}

	s := &tendermintScheduler{
		logger:  logging.GetLogger("scheduler/tendermint"),
		service: service,
	}
	s.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		currentCommittees, err := s.getCurrentCommittees()
		if err != nil {
			s.logger.Error("couldn't get current committees. won't send them. good luck to the subscriber",
				"err", err,
			)
			return
		}
		for _, c := range currentCommittees {
			ch.In() <- c
		}
	})

	go s.worker(ctx)

	return s, nil
}
