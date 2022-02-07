// Package registry implements the tendermint backed registry backend.
package registry

import (
	"context"
	"fmt"

	"github.com/eapache/channels"
	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry"
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
}

// NodeListEpochInternalEvent is the per-epoch node list event.
type NodeListEpochInternalEvent struct {
	Height int64 `json:"height"`
}

func (sc *serviceClient) Querier() *app.QueryFactory {
	return sc.querier
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

func (sc *serviceClient) WatchEntities(ctx context.Context) (<-chan *api.EntityEvent, pubsub.ClosableSubscription, error) {
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

func (sc *serviceClient) WatchNodes(ctx context.Context) (<-chan *api.NodeEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeEvent)
	sub := sc.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) WatchNodeList(ctx context.Context) (<-chan *api.NodeList, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeList)
	sub := sc.nodeListNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (sc *serviceClient) GetRuntime(ctx context.Context, query *api.NamespaceQuery) (*api.Runtime, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Runtime(ctx, query.ID)
}

func (sc *serviceClient) WatchRuntimes(ctx context.Context) (<-chan *api.Runtime, pubsub.ClosableSubscription, error) {
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
	var results *tmrpctypes.ResultBlockResults
	results, err := sc.backend.GetBlockResults(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}
	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get tendermint transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results.
	blockEvs, _, err := EventsFromTendermint(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	blockEvs, _, err = EventsFromTendermint(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		txEvs, _, txErr := EventsFromTendermint(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, txEvs...)
	}

	return events, nil
}

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewStaticServiceDescriptor(api.ModuleName, app.EventType, []tmpubsub.Query{app.QueryApp})
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx tmtypes.Tx, ev *tmabcitypes.Event) error {
	events, nodeListEvents, err := EventsFromTendermint(tx, height, []tmabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("scheduler: failed to process tendermint events: %w", err)
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
		if ev.RuntimeEvent != nil {
			sc.runtimeNotifier.Broadcast(ev.RuntimeEvent.Runtime)
		}
	}

	return nil
}

// EventsFromTendermint extracts registry events from tendermint events.
func EventsFromTendermint(
	tx tmtypes.Tx,
	height int64,
	tmEvents []tmabcitypes.Event,
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
			case tmapi.IsAttributeKind(key, &api.NodeListEpochEvent{}):
				// Node list epoch event.
				nodeListEvents = append(nodeListEvents, &NodeListEpochInternalEvent{Height: height})
			case tmapi.IsAttributeKind(key, &api.RuntimeEvent{}):
				// Runtime registered event.
				var e api.RuntimeEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt Runtime event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, RuntimeEvent: &e})
			case tmapi.IsAttributeKind(key, &api.EntityEvent{}):
				// Entity event.
				var e api.EntityEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt Entity event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, EntityEvent: &e})
			case tmapi.IsAttributeKind(key, &api.NodeEvent{}):
				// Node event.
				var e api.NodeEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt Node event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, TxHash: txHash, NodeEvent: &e})
			case tmapi.IsAttributeKind(key, &api.NodeUnfrozenEvent{}):
				// Node unfrozen event.
				var e api.NodeUnfrozenEvent
				if err := cbor.Unmarshal(val, &e); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt NodeUnfrozen event: %w", err))
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

// New constructs a new tendermint backed registry Backend instance.
func New(ctx context.Context, backend tmapi.Backend) (ServiceClient, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}

	sc := &serviceClient{
		logger:         logging.GetLogger("registry/tendermint"),
		backend:        backend,
		querier:        a.QueryFactory().(*app.QueryFactory),
		entityNotifier: pubsub.NewBroker(false),
		nodeNotifier:   pubsub.NewBroker(false),
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
