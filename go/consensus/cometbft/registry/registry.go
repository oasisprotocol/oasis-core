// Package registry implements the CometBFT backed registry backend.
package registry

import (
	"context"
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
)

// ServiceClient is the registry service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type serviceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	backend tmapi.Backend
	querier *app.QueryFactory

	entityNotifier   *pubsub.Broker
	nodeNotifier     *pubsub.Broker
	nodeListNotifier *pubsub.Broker
	runtimeNotifier  *pubsub.Broker
	eventNotifier    *pubsub.Broker
}

// NodeListEpochInternalEvent is the per-epoch node list event.
type NodeListEpochInternalEvent struct {
	Height int64 `json:"height"`
}

func (sc *serviceClient) GetEntity(ctx context.Context, query *api.IDQuery) (*entity.Entity, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Entity(ctx, query.ID)
}

func (sc *serviceClient) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Entities(ctx)
}

func (sc *serviceClient) WatchEntities(context.Context) (<-chan *api.EntityEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.EntityEvent)
	sub := sc.entityNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) GetNode(ctx context.Context, query *api.IDQuery) (*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Node(ctx, query.ID)
}

func (sc *serviceClient) GetNodeStatus(ctx context.Context, query *api.IDQuery) (*api.NodeStatus, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeStatus(ctx, query.ID)
}

func (sc *serviceClient) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Nodes(ctx)
}

func (sc *serviceClient) GetNodeByConsensusAddress(ctx context.Context, query *api.ConsensusAddressQuery) (*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeByConsensusAddress(ctx, query.Address)
}

func (sc *serviceClient) WatchNodes(context.Context) (<-chan *api.NodeEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeEvent)
	sub := sc.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) WatchNodeList(context.Context) (<-chan *api.NodeList, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeList)
	sub := sc.nodeListNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) GetRuntime(ctx context.Context, query *api.GetRuntimeQuery) (*api.Runtime, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Runtime(ctx, query.ID, query.IncludeSuspended)
}

func (sc *serviceClient) WatchRuntimes(_ context.Context) (<-chan *api.Runtime, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Runtime)
	sub := sc.runtimeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) Cleanup() {
}

func (sc *serviceClient) GetRuntimes(ctx context.Context, query *api.GetRuntimesQuery) ([]*api.Runtime, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}
	return q.Runtimes(ctx, query.IncludeSuspended)
}

func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *serviceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	var results *cmtrpctypes.ResultBlockResults
	results, err := sc.backend.GetCometBFTBlockResults(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}
	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, _, err := EventsFromCometBFT(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		txEvs, _, txErr := EventsFromCometBFT(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, txEvs...)
	}

	// Decode events from block results (at the end of the block).
	blockEvs, _, err = EventsFromCometBFT(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

// WatchEvents implements api.Backend.
func (sc *serviceClient) WatchEvents(_ context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}
	return q.ConsensusParameters(ctx)
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
	events, nodeListEvents, err := EventsFromCometBFT(tx, height, []cmtabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("scheduler: failed to process cometbft events: %w", err)
	}

	// Process node list events.
	for _, ev := range nodeListEvents {
		nl, err := sc.getNodeList(ctx, height)
		if err != nil {
			sc.logger.Error("worker: failed to get node list",
				"height", ev.Height,
				"err", err,
			)
			continue
		}
		sc.nodeListNotifier.Broadcast(nl)
	}

	// Notify subscribers of events.
	for _, ev := range events {
		if ev.EntityEvent != nil {
			sc.entityNotifier.Broadcast(ev.EntityEvent)
		}
		if ev.NodeEvent != nil {
			sc.nodeNotifier.Broadcast(ev.NodeEvent)
		}
		if ev.RuntimeStartedEvent != nil {
			sc.runtimeNotifier.Broadcast(ev.RuntimeStartedEvent.Runtime)
		}
		sc.eventNotifier.Broadcast(ev)
	}

	return nil
}

// EventsFromCometBFT extracts registry events from CometBFT events.
func EventsFromCometBFT(
	tx cmttypes.Tx,
	height int64,
	tmEvents []cmtabcitypes.Event,
) ([]*api.Event, []*NodeListEpochInternalEvent, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*api.Event
	var nodeListEvents []*NodeListEpochInternalEvent
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the registry app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &api.NodeListEpochEvent{}):
				// Node list epoch event (value is ignored).
				nodeListEvents = append(nodeListEvents, &NodeListEpochInternalEvent{Height: height})
			case eventsAPI.IsAttributeKind(key, &api.RuntimeStartedEvent{}):
				// Runtime started event.
				var e api.RuntimeStartedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt RuntimeStarted event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, RuntimeStartedEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.RuntimeSuspendedEvent{}):
				// Runtime suspended event.
				var e api.RuntimeSuspendedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt RuntimeSuspended event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, RuntimeSuspendedEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.EntityEvent{}):
				// Entity event.
				var e api.EntityEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt Entity event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, EntityEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.NodeEvent{}):
				// Node event.
				var e api.NodeEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt Node event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, NodeEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.NodeUnfrozenEvent{}):
				// Node unfrozen event.
				var e api.NodeUnfrozenEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt NodeUnfrozen event: %w", err))
					continue
				}
				events = append(events, &api.Event{Height: height, TxHash: txHash, NodeUnfrozenEvent: &e})
			}
		}
	}
	return events, nodeListEvents, errs
}

func (sc *serviceClient) getNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	// Generate the nodelist.
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	nodes, err := q.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: failed to query nodes: %w", err)
	}

	api.SortNodeList(nodes)

	return &api.NodeList{
		Nodes: nodes,
	}, nil
}

// New constructs a new CometBFT backed registry Backend instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	// Initialize and register the CometBFT service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	sc := &serviceClient{
		logger:         logging.GetLogger("cometbft/registry"),
		backend:        backend,
		querier:        a.QueryFactory().(*app.QueryFactory),
		entityNotifier: pubsub.NewBroker(false),
		nodeNotifier:   pubsub.NewBroker(false),
		eventNotifier:  pubsub.NewBroker(false),
	}
	sc.nodeListNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		wr := ch.In()
		nodeList, err := sc.getNodeList(ctx, consensus.HeightLatest)
		if err != nil {
			sc.logger.Error("node list notifier: unable to get a list of nodes",
				"err", err,
			)
			return
		}

		wr <- nodeList
	})
	sc.runtimeNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		wr := ch.In()
		runtimes, err := sc.GetRuntimes(ctx, &api.GetRuntimesQuery{Height: consensus.HeightLatest, IncludeSuspended: true})
		if err != nil {
			sc.logger.Error("runtime notifier: unable to get a list of runtimes",
				"err", err,
			)
			return
		}

		for _, v := range runtimes {
			wr <- v
		}
	})

	return sc, nil
}
