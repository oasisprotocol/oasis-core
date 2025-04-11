// Package keymanager provides the CometBFT backed key manager management
// implementation.
package secrets

import (
	"context"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// ServiceClient is the key manager secrets service client.
type ServiceClient struct {
	logger *logging.Logger

	querier           QueryFactory
	statusNotifier    *pubsub.Broker
	mstSecretNotifier *pubsub.Broker
	ephSecretNotifier *pubsub.Broker
}

// New constructs a new CometBFT backed key manager secrets service client.
func New(querier QueryFactory) *ServiceClient {
	return &ServiceClient{
		logger:            logging.GetLogger("cometbft/keymanager/secrets"),
		querier:           querier,
		statusNotifier:    pubsub.NewBroker(false),
		mstSecretNotifier: pubsub.NewBroker(false),
		ephSecretNotifier: pubsub.NewBroker(false),
	}
}

func (sc *ServiceClient) GetStatus(ctx context.Context, query *registry.NamespaceQuery) (*secrets.Status, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Status(ctx, query.ID)
}

func (sc *ServiceClient) GetStatuses(ctx context.Context, height int64) ([]*secrets.Status, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Statuses(ctx)
}

func (sc *ServiceClient) WatchStatuses(ctx context.Context) (<-chan *secrets.Status, pubsub.ClosableSubscription, error) {
	hook := sc.statusNotifierHook(ctx)
	ch := make(chan *secrets.Status)
	sub := sc.statusNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*secrets.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) GetMasterSecret(ctx context.Context, query *registry.NamespaceQuery) (*secrets.SignedEncryptedMasterSecret, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.MasterSecret(ctx, query.ID)
}

func (sc *ServiceClient) GetEphemeralSecret(ctx context.Context, query *registry.NamespaceQuery) (*secrets.SignedEncryptedEphemeralSecret, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.EphemeralSecret(ctx, query.ID)
}

func (sc *ServiceClient) WatchMasterSecrets(context.Context) (<-chan *secrets.SignedEncryptedMasterSecret, pubsub.ClosableSubscription, error) {
	sub := sc.mstSecretNotifier.Subscribe()
	ch := make(chan *secrets.SignedEncryptedMasterSecret)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) WatchEphemeralSecrets(context.Context) (<-chan *secrets.SignedEncryptedEphemeralSecret, pubsub.ClosableSubscription, error) {
	sub := sc.ephSecretNotifier.Subscribe()
	ch := make(chan *secrets.SignedEncryptedEphemeralSecret)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) DeliverEvent(ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		if events.IsAttributeKind(pair.GetKey(), &secrets.StatusUpdateEvent{}) {
			var event secrets.StatusUpdateEvent
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
		if events.IsAttributeKind(pair.GetKey(), &secrets.MasterSecretPublishedEvent{}) {
			var event secrets.MasterSecretPublishedEvent
			if err := events.DecodeValue(pair.GetValue(), &event); err != nil {
				sc.logger.Error("worker: failed to get master secret from tag",
					"err", err,
				)
				continue
			}

			sc.mstSecretNotifier.Broadcast(event.Secret)
		}
		if events.IsAttributeKind(pair.GetKey(), &secrets.EphemeralSecretPublishedEvent{}) {
			var event secrets.EphemeralSecretPublishedEvent
			if err := events.DecodeValue(pair.GetValue(), &event); err != nil {
				sc.logger.Error("worker: failed to get ephemeral secret from tag",
					"err", err,
				)
				continue
			}

			sc.ephSecretNotifier.Broadcast(event.Secret)
		}
	}
	return nil
}

func (sc *ServiceClient) statusNotifierHook(ctx context.Context) pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		statuses, err := sc.GetStatuses(ctx, consensus.HeightLatest)
		if err != nil {
			sc.logger.Error("status notifier: unable to get a list of statuses",
				"err", err,
			)
			return
		}

		for _, v := range statuses {
			ch.In() <- v
		}
	}
}
