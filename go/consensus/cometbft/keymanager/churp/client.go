package churp

import (
	"context"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
)

// ServiceClient is the key manager CHURP service client.
type ServiceClient struct {
	logger *logging.Logger

	querier        QueryFactory
	statusNotifier *pubsub.Broker
}

// New constructs a new CometBFT backed key manager CHURP service client.
func New(querier QueryFactory) *ServiceClient {
	return &ServiceClient{
		logger:         logging.GetLogger("cometbft/keymanager/churp"),
		querier:        querier,
		statusNotifier: pubsub.NewBroker(false),
	}
}

// ConsensusParameters implements churp.Backend.
func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*churp.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

// Status implements churp.Backend.
func (sc *ServiceClient) Status(ctx context.Context, query *churp.StatusQuery) (*churp.Status, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Status(ctx, query.RuntimeID, query.ChurpID)
}

// Statuses implements churp.Backend.
func (sc *ServiceClient) Statuses(ctx context.Context, query *api.NamespaceQuery) ([]*churp.Status, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Statuses(ctx, query.ID)
}

// AllStatuses implements churp.Backend.
func (sc *ServiceClient) AllStatuses(ctx context.Context, height int64) ([]*churp.Status, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.AllStatuses(ctx)
}

// StateToGenesis implements churp.Backend.
func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*churp.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

// WatchStatuses implements churp.Backend.
func (sc *ServiceClient) WatchStatuses(ctx context.Context) (<-chan *churp.Status, pubsub.ClosableSubscription, error) {
	hook := sc.statusNotifierHook(ctx)
	ch := make(chan *churp.Status)
	sub := sc.statusNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) DeliverEvent(ev *cmtabcitypes.Event) error {
	for _, pair := range ev.GetAttributes() {
		key := pair.GetKey()
		val := pair.GetValue()

		if events.IsAttributeKind(key, &churp.CreateEvent{}) {
			var event churp.CreateEvent
			if err := events.DecodeValue(val, &event); err != nil {
				sc.logger.Error("worker: failed to get status from tag",
					"err", err,
				)
				continue
			}

			sc.statusNotifier.Broadcast(event.Status)
		}
		if events.IsAttributeKind(key, &churp.UpdateEvent{}) {
			var event churp.UpdateEvent
			if err := events.DecodeValue(val, &event); err != nil {
				sc.logger.Error("worker: failed to get status from tag",
					"err", err,
				)
				continue
			}

			sc.statusNotifier.Broadcast(event.Status)
		}
	}
	return nil
}

func (sc *ServiceClient) statusNotifierHook(ctx context.Context) pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		statuses, err := sc.AllStatuses(ctx, consensus.HeightLatest)
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
