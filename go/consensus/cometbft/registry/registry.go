// Package registry implements the CometBFT backed registry backend.
package registry

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
)

// ServiceClient is the registry service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	consensus  consensus.Backend
	querier    *app.QueryFactory
	descriptor *tmapi.ServiceDescriptor

	entityNotifier   *pubsub.Broker
	nodeNotifier     *pubsub.Broker
	nodeListNotifier *pubsub.Broker
	runtimeNotifier  *pubsub.Broker
	eventNotifier    *pubsub.Broker
}

// New constructs a new CometBFT backed registry service client.
func New(consensus consensus.Backend, querier *app.QueryFactory) *ServiceClient {
	descriptor := tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []cmtpubsub.Query{app.QueryApp})

	return &ServiceClient{
		logger:           logging.GetLogger("cometbft/registry"),
		consensus:        consensus,
		querier:          querier,
		descriptor:       descriptor,
		entityNotifier:   pubsub.NewBroker(false),
		nodeNotifier:     pubsub.NewBroker(false),
		nodeListNotifier: pubsub.NewBroker(false),
		runtimeNotifier:  pubsub.NewBroker(false),
		eventNotifier:    pubsub.NewBroker(false),
	}
}

// NodeListEpochInternalEvent is the per-epoch node list event.
type NodeListEpochInternalEvent struct {
	Height int64 `json:"height"`
}

func (sc *ServiceClient) GetEntity(ctx context.Context, query *api.IDQuery) (*entity.Entity, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Entity(ctx, query.ID)
}

func (sc *ServiceClient) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Entities(ctx)
}

func (sc *ServiceClient) WatchEntities(context.Context) (<-chan *api.EntityEvent, pubsub.ClosableSubscription, error) {
	ch := make(chan *api.EntityEvent)
	sub := sc.entityNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) GetNode(ctx context.Context, query *api.IDQuery) (*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Node(ctx, query.ID)
}

func (sc *ServiceClient) GetNodeStatus(ctx context.Context, query *api.IDQuery) (*api.NodeStatus, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeStatus(ctx, query.ID)
}

func (sc *ServiceClient) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Nodes(ctx)
}

func (sc *ServiceClient) GetNodeByConsensusAddress(ctx context.Context, query *api.ConsensusAddressQuery) (*node.Node, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeByConsensusAddress(ctx, query.Address)
}

func (sc *ServiceClient) WatchNodes(context.Context) (<-chan *api.NodeEvent, pubsub.ClosableSubscription, error) {
	ch := make(chan *api.NodeEvent)
	sub := sc.nodeNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) WatchNodeList(ctx context.Context) (<-chan *api.NodeList, pubsub.ClosableSubscription, error) {
	hook := sc.nodeListNotifierHook(ctx)
	ch := make(chan *api.NodeList)
	sub := sc.nodeListNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) GetRuntime(ctx context.Context, query *api.GetRuntimeQuery) (*api.Runtime, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Runtime(ctx, query.ID, query.IncludeSuspended)
}

func (sc *ServiceClient) WatchRuntimes(ctx context.Context) (<-chan *api.Runtime, pubsub.ClosableSubscription, error) {
	hook := sc.runtimeNotifierHook(ctx)
	ch := make(chan *api.Runtime)
	sub := sc.runtimeNotifier.SubscribeEx(hook)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) GetRuntimes(ctx context.Context, query *api.GetRuntimesQuery) ([]*api.Runtime, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}
	return q.Runtimes(ctx, query.IncludeSuspended)
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	results, err := tmapi.GetBlockResults(ctx, height, sc.consensus)
	if err != nil {
		sc.logger.Error("failed to get block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.consensus.GetTransactions(ctx, results.Height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", results.Height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, _, err := EventsFromCometBFT(nil, results.Height, results.Meta.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.Meta.TxsResults {
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
	blockEvs, _, err = EventsFromCometBFT(nil, results.Height, results.Meta.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

// WatchEvents implements api.Backend.
func (sc *ServiceClient) WatchEvents(_ context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	ch := make(chan *api.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}
	return q.ConsensusParameters(ctx)
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() *tmapi.ServiceDescriptor {
	return sc.descriptor
}

// DeliverEvent implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
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

func (sc *ServiceClient) getNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
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

func (sc *ServiceClient) nodeListNotifierHook(ctx context.Context) pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		nodeList, err := sc.getNodeList(ctx, consensus.HeightLatest)
		if err != nil {
			sc.logger.Error("node list notifier: unable to get a list of nodes",
				"err", err,
			)
			return
		}

		ch.In() <- nodeList
	}
}

func (sc *ServiceClient) runtimeNotifierHook(ctx context.Context) pubsub.OnSubscribeHook {
	return func(ch channels.Channel) {
		runtimes, err := sc.GetRuntimes(ctx, &api.GetRuntimesQuery{Height: consensus.HeightLatest, IncludeSuspended: true})
		if err != nil {
			sc.logger.Error("runtime notifier: unable to get a list of runtimes",
				"err", err,
			)
			return
		}

		for _, v := range runtimes {
			ch.In() <- v
		}
	}
}
