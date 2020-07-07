// Package registry implements the tendermint backed registry backend.
package registry

import (
	"bytes"
	"context"
	"fmt"

	"github.com/eapache/channels"
	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/service"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
)

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
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

func (tb *tendermintBackend) Querier() *app.QueryFactory {
	return tb.querier
}

func (tb *tendermintBackend) GetEntity(ctx context.Context, query *api.IDQuery) (*entity.Entity, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Entity(ctx, query.ID)
}

func (tb *tendermintBackend) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Entities(ctx)
}

func (tb *tendermintBackend) WatchEntities(ctx context.Context) (<-chan *api.EntityEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.EntityEvent)
	sub := tb.entityNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) GetNode(ctx context.Context, query *api.IDQuery) (*node.Node, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Node(ctx, query.ID)
}

func (tb *tendermintBackend) GetNodeStatus(ctx context.Context, query *api.IDQuery) (*api.NodeStatus, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeStatus(ctx, query.ID)
}

func (tb *tendermintBackend) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Nodes(ctx)
}

func (tb *tendermintBackend) GetNodeByConsensusAddress(ctx context.Context, query *api.ConsensusAddressQuery) (*node.Node, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.NodeByConsensusAddress(ctx, query.Address)
}

func (tb *tendermintBackend) WatchNodes(ctx context.Context) (<-chan *api.NodeEvent, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeEvent)
	sub := tb.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) WatchNodeList(ctx context.Context) (<-chan *api.NodeList, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.NodeList)
	sub := tb.nodeListNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) GetRuntime(ctx context.Context, query *api.NamespaceQuery) (*api.Runtime, error) {
	q, err := tb.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Runtime(ctx, query.ID)
}

func (tb *tendermintBackend) WatchRuntimes(ctx context.Context) (<-chan *api.Runtime, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *api.Runtime)
	sub := tb.runtimeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

func (tb *tendermintBackend) Cleanup() {
}

func (tb *tendermintBackend) GetRuntimes(ctx context.Context, height int64) ([]*api.Runtime, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Runtimes(ctx)
}

func (tb *tendermintBackend) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) ([]api.Event, error) {
	// Get block results at given height.
	var results *tmrpctypes.ResultBlockResults
	results, err := tb.service.GetBlockResults(height)
	if err != nil {
		tb.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}
	// Get transactions at given height.
	txns, err := tb.service.GetTransactions(ctx, height)
	if err != nil {
		tb.logger.Error("failed to get tendermint transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []api.Event
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

func (tb *tendermintBackend) worker(ctx context.Context) {
	// Subscribe to transactions which modify state.
	sub, err := tb.service.Subscribe("registry-worker", app.QueryApp)
	if err != nil {
		tb.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer tb.service.Unsubscribe("registry-worker", app.QueryApp) // nolint: errcheck

	// Process transactions and emit notifications for our subscribers.
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
		case tmtypes.EventDataTx:
			tb.onEventDataTx(ctx, ev)
		default:
		}
	}
}

func (tb *tendermintBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	tmEvents := append([]tmabcitypes.Event{}, ev.ResultBeginBlock.GetEvents()...)
	tmEvents = append(tmEvents, ev.ResultEndBlock.GetEvents()...)
	events, nodeListEvents, err := EventsFromTendermint(nil, ev.Block.Header.Height, tmEvents)
	if err != nil {
		tb.logger.Error("error processing registry events", "err", err)
	}
	tb.processNodeListEvents(ctx, nodeListEvents)
	tb.notifyEvents(ctx, events)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, ev tmtypes.EventDataTx) {
	events, nodeListEvents, err := EventsFromTendermint(ev.Tx, ev.Height, ev.Result.Events)
	if err != nil {
		tb.logger.Error("error processing registry events", "err", err)
	}
	tb.processNodeListEvents(ctx, nodeListEvents)
	tb.notifyEvents(ctx, events)
}

func (tb *tendermintBackend) processNodeListEvents(ctx context.Context, events []NodeListEpochInternalEvent) {
	for _, ev := range events {
		nl, err := tb.getNodeList(ctx, ev.Height)
		if err != nil {
			tb.logger.Error("worker: failed to get node list",
				"height", ev.Height,
				"err", err,
			)
			continue
		}
		tb.nodeListNotifier.Broadcast(nl)
	}
}

func (tb *tendermintBackend) notifyEvents(ctx context.Context, events []api.Event) {
	for _, ev := range events {
		if ev.EntityEvent != nil {
			tb.entityNotifier.Broadcast(ev.EntityEvent)
		}
		if ev.NodeEvent != nil {
			tb.nodeNotifier.Broadcast(ev.NodeEvent)
		}
		if ev.RuntimeEvent != nil {
			tb.runtimeNotifier.Broadcast(ev.RuntimeEvent.Runtime)
		}
	}
}

// EventsFromTendermint extracts registry events from tendermint events.
func EventsFromTendermint(
	tx tmtypes.Tx,
	height int64,
	tmEvents []tmabcitypes.Event,
) ([]api.Event, []NodeListEpochInternalEvent, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []api.Event
	var nodeListEvents []NodeListEpochInternalEvent
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
			case bytes.Equal(key, app.KeyRegistryNodeListEpoch):
				// Node list epoch event.
				nodeListEvents = append(nodeListEvents, NodeListEpochInternalEvent{Height: height})
			case bytes.Equal(key, app.KeyNodesExpired):
				// Nodes expired event.
				var nodes []*node.Node
				if err := cbor.Unmarshal(val, &nodes); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt NodesExpired event: %w", err))
					continue
				}

				// Generate node deregistration events.
				for _, node := range nodes {
					ne := &api.NodeEvent{
						Node:           node,
						IsRegistration: false,
					}
					events = append(events, api.Event{Height: height, TxHash: txHash, NodeEvent: ne})
				}
			case bytes.Equal(key, app.KeyRuntimeRegistered):
				// Runtime registered event.
				var rt api.Runtime
				if err := cbor.Unmarshal(val, &rt); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt RuntimeRegistered event: %w", err))
					continue
				}

				evt := api.Event{
					Height:       height,
					TxHash:       txHash,
					RuntimeEvent: &api.RuntimeEvent{Runtime: &rt},
				}
				events = append(events, evt)
			case bytes.Equal(key, app.KeyEntityRegistered):
				// Entity registered event.
				var ent entity.Entity
				if err := cbor.Unmarshal(val, &ent); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt EntityRegistered event: %w", err))
					continue
				}

				eev := &api.EntityEvent{
					Entity:         &ent,
					IsRegistration: true,
				}
				events = append(events, api.Event{Height: height, TxHash: txHash, EntityEvent: eev})
			case bytes.Equal(key, app.KeyEntityDeregistered):
				// Entity deregistered event.
				var dereg app.EntityDeregistration
				if err := cbor.Unmarshal(val, &dereg); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt EntityDeregistered event: %w", err))
					continue
				}

				eev := &api.EntityEvent{
					Entity:         &dereg.Entity,
					IsRegistration: false,
				}
				events = append(events, api.Event{Height: height, TxHash: txHash, EntityEvent: eev})
			case bytes.Equal(key, app.KeyNodeRegistered):
				// Node registered event.
				var n node.Node
				if err := cbor.Unmarshal(val, &n); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt NodeRegistered event: %w", err))
					continue
				}

				nev := &api.NodeEvent{
					Node:           &n,
					IsRegistration: true,
				}
				events = append(events, api.Event{Height: height, TxHash: txHash, NodeEvent: nev})
			case bytes.Equal(key, app.KeyNodeUnfrozen):
				// Node unfrozen event.
				var nid signature.PublicKey
				if err := cbor.Unmarshal(val, &nid); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("registry: corrupt NodeUnfrozen event: %w", err))
					continue
				}
				evt := api.Event{
					Height: height,
					TxHash: txHash,
					NodeUnfrozenEvent: &api.NodeUnfrozenEvent{
						NodeID: nid,
					},
				}
				events = append(events, evt)
			}
		}
	}
	return events, nodeListEvents, errs
}

func (tb *tendermintBackend) getNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	// Generate the nodelist.
	q, err := tb.querier.QueryAt(ctx, height)
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
func New(ctx context.Context, service service.TendermintService) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		logger:           logging.GetLogger("registry/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		entityNotifier:   pubsub.NewBroker(false),
		nodeNotifier:     pubsub.NewBroker(false),
		nodeListNotifier: pubsub.NewBroker(true),
	}
	tb.runtimeNotifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		wr := ch.In()
		runtimes, err := tb.GetRuntimes(ctx, consensus.HeightLatest)
		if err != nil {
			tb.logger.Error("runtime notifier: unable to get a list of runtimes",
				"err", err,
			)
			return
		}

		for _, v := range runtimes {
			wr <- v
		}
	})

	go tb.worker(ctx)

	return tb, nil
}
