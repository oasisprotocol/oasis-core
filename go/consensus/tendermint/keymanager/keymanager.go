// Package keymanager provides the tendermint backed key manager management
// implementation.
package keymanager

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
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

	querier        *app.QueryFactory
	statusNotifier *pubsub.Broker
	secretNotifier *pubsub.Broker
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
	sub := sc.statusNotifier.Subscribe()
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

func (sc *serviceClient) GetEphemeralSecret(ctx context.Context, query *registry.NamespaceEpochQuery) (*api.SignedEncryptedEphemeralSecret, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.EphemeralSecret(ctx, query.ID, query.Epoch)
}

func (sc *serviceClient) WatchEphemeralSecrets() (<-chan *api.SignedEncryptedEphemeralSecret, *pubsub.Subscription) {
	sub := sc.secretNotifier.Subscribe()
	ch := make(chan *api.SignedEncryptedEphemeralSecret)
	sub.Unwrap(ch)

	return ch, sub
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		if events.IsAttributeKind(pair.GetKey(), &api.StatusUpdateEvent{}) {
			var event api.StatusUpdateEvent
			if err := events.DecodeValue(pair.GetValue(), &event); err != nil {
				sc.logger.Error("worker: failed to get statuses from tag",
					"err", err,
				)
				continue
			}

			for _, status := range event.Statuses {
				sc.statusNotifier.Broadcast(status)
			}
		}
		if events.IsAttributeKind(pair.GetKey(), &api.EphemeralSecretPublishedEvent{}) {
			var event api.EphemeralSecretPublishedEvent
			if err := events.DecodeValue(pair.GetValue(), &event); err != nil {
				sc.logger.Error("worker: failed to get ephemeral secret from tag",
					"err", err,
				)
				continue
			}

			sc.secretNotifier.Broadcast(event.Secret)
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
	sc.statusNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
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
	sc.secretNotifier = pubsub.NewBroker(false)

	return sc, nil
}
