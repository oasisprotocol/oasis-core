// Package registry implements the tendermint backed registry backend.
package registry

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/registry/api"
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

func (tb *tendermintBackend) GetNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	return tb.getNodeList(ctx, height)
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

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) (*[]api.Event, error) {
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

	// Decode events from block results.
	tmEvents := append(results.BeginBlockEvents, results.EndBlockEvents...)
	for _, txResults := range results.TxsResults {
		tmEvents = append(tmEvents, txResults.Events...)
	}
	return tb.onABCIEvents(ctx, tmEvents, height, false)
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
	events := append([]abcitypes.Event{}, ev.ResultBeginBlock.GetEvents()...)
	events = append(events, ev.ResultEndBlock.GetEvents()...)

	_, _ = tb.onABCIEvents(ctx, events, ev.Block.Header.Height, true)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, tx tmtypes.EventDataTx) {
	_, _ = tb.onABCIEvents(ctx, tx.Result.Events, tx.Height, true)
}

func (tb *tendermintBackend) onABCIEvents(ctx context.Context, tmEvents []abcitypes.Event, height int64, doBroadcast bool) (*[]api.Event, error) { // nolint: gocyclo
	events := []api.Event{}
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the registry app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()
			if bytes.Equal(key, app.KeyNodesExpired) {
				// Nodes expired event.
				var nodes []*node.Node
				if err := cbor.Unmarshal(val, &nodes); err != nil {
					tb.logger.Error("worker: failed to get nodes from tag",
						"err", err,
					)
					if !doBroadcast {
						return nil, errors.Wrap(err, "registry: corrupt NodesExpired event")
					}
				}

				if doBroadcast {
					for _, node := range nodes {
						tb.nodeNotifier.Broadcast(&api.NodeEvent{
							Node:           node,
							IsRegistration: false,
						})
					}
				} else {
					evt := api.Event{
						NodesExpiredEvent: &api.NodesExpiredEvent{
							Nodes: nodes,
						},
					}
					events = append(events, evt)
				}
			} else if bytes.Equal(key, app.KeyRuntimeRegistered) {
				// Runtime registered event.
				var rt api.Runtime
				if err := cbor.Unmarshal(val, &rt); err != nil {
					tb.logger.Error("worker: failed to get runtime from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, errors.Wrap(err, "registry: corrupt RuntimeRegistered event")
					}
				}

				if doBroadcast {
					tb.runtimeNotifier.Broadcast(&rt)
				} else {
					evt := api.Event{
						RuntimeEvent: &api.RuntimeEvent{Runtime: &rt},
					}
					events = append(events, evt)
				}
			} else if bytes.Equal(key, app.KeyEntityRegistered) {
				// Entity registered event.
				var ent entity.Entity
				if err := cbor.Unmarshal(val, &ent); err != nil {
					tb.logger.Error("worker: failed to get entity from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, errors.Wrap(err, "registry: corrupt EntityRegistered event")
					}
				}

				eev := &api.EntityEvent{
					Entity:         &ent,
					IsRegistration: true,
				}

				if doBroadcast {
					tb.entityNotifier.Broadcast(eev)
				} else {
					events = append(events, api.Event{EntityEvent: eev})
				}
			} else if bytes.Equal(key, app.KeyEntityDeregistered) {
				// Entity deregistered event.
				var dereg app.EntityDeregistration
				if err := cbor.Unmarshal(val, &dereg); err != nil {
					tb.logger.Error("worker: failed to get entity deregistration from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, errors.Wrap(err, "registry: corrupt EntityDeregistered event")
					}
				}

				eev := &api.EntityEvent{
					Entity:         &dereg.Entity,
					IsRegistration: false,
				}

				if doBroadcast {
					tb.entityNotifier.Broadcast(eev)
				} else {
					events = append(events, api.Event{EntityEvent: eev})
				}
			} else if bytes.Equal(key, app.KeyRegistryNodeListEpoch) && doBroadcast {
				// Node list epoch event.
				nl, err := tb.getNodeList(ctx, height)
				if err != nil {
					tb.logger.Error("worker: failed to get node list",
						"height", height,
						"err", err,
					)
					continue
				}
				tb.nodeListNotifier.Broadcast(nl)
			} else if bytes.Equal(key, app.KeyNodeRegistered) {
				// Node registered event.
				var n node.Node
				if err := cbor.Unmarshal(val, &n); err != nil {
					tb.logger.Error("worker: failed to get node from tag",
						"err", err,
					)
					if doBroadcast {
						continue
					} else {
						return nil, errors.Wrap(err, "registry: corrupt NodeRegistered event")
					}
				}

				nev := &api.NodeEvent{
					Node:           &n,
					IsRegistration: true,
				}

				if doBroadcast {
					tb.nodeNotifier.Broadcast(nev)
				} else {
					events = append(events, api.Event{NodeEvent: nev})
				}
			} else if bytes.Equal(key, app.KeyNodeUnfrozen) && !doBroadcast {
				// Node unfrozen event.
				var nid signature.PublicKey
				if err := cbor.Unmarshal(val, &nid); err != nil {
					return nil, errors.Wrap(err, "registry: corrupt NodeUnfrozen event")
				}
				evt := api.Event{
					NodeUnfrozenEvent: &api.NodeUnfrozenEvent{
						NodeID: nid,
					},
				}
				events = append(events, evt)
			}
		}
	}
	return &events, nil
}

func (tb *tendermintBackend) getNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	// Generate the nodelist.
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	nodes, err := q.Nodes(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "registry: failed to query nodes")
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
	tb.runtimeNotifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
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
