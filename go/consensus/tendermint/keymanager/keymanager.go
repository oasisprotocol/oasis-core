// Package keymanager provides the tendermint backed key manager management
// implementation.
package keymanager

import (
	"context"
	"fmt"

	"github.com/eapache/channels"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// ServiceClient is the registry service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	querier  *app.QueryFactory
	notifier *pubsub.Broker
}

func (sc *serviceClient) GetStatus(ctx context.Context, query *registry.NamespaceQuery) (*api.Status, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Status(ctx, query.ID)
}

func (sc *serviceClient) GetStatuses(ctx context.Context, height int64) ([]*api.Status, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Statuses(ctx)
}

func (sc *serviceClient) WatchStatuses() (<-chan *api.Status, *pubsub.Subscription) {
	sub := sc.notifier.Subscribe()
	ch := make(chan *api.Status)
	sub.Unwrap(ch)

	return ch, sub
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx tmtypes.Tx, ev *tmabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		if tmapi.IsAttributeKind(pair.GetKey(), &api.StatusUpdateEvent{}) {
			var event api.StatusUpdateEvent
			if err := cbor.Unmarshal(pair.GetValue(), &event); err != nil {
				sc.logger.Error("worker: failed to get statuses from tag",
					"err", err,
				)
				continue
			}

			for _, status := range event.Statuses {
				sc.notifier.Broadcast(status)
			}
		}
	}
	return nil
}

// New constructs a new tendermint backed key manager management Backend
// instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, fmt.Errorf("keymanager/tendermint: failed to register app: %w", err)
	}

	sc := &serviceClient{
		logger:  logging.GetLogger("keymanager/tendermint"),
		querier: a.QueryFactory().(*app.QueryFactory),
	}
	sc.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		statuses, err := sc.GetStatuses(ctx, consensus.HeightLatest)
		if err != nil {
			sc.logger.Error("status notifier: unable to get a list of statuses",
				"err", err,
			)
			return
		}

		wr := ch.In()
		for _, v := range statuses {
			wr <- v
		}
	})

	return sc, nil
}
