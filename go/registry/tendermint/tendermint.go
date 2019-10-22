// Package tendermint implements the tendermint backed registry backend.
package tendermint

import (
	"bytes"
	"context"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/registry/api"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = tmapi.BackendName

var (
	_ api.Backend = (*tendermintBackend)(nil)
)

type tendermintBackend struct {
	logger *logging.Logger

	service service.TendermintService
	querier *app.QueryFactory

	cfg *api.Config

	entityNotifier   *pubsub.Broker
	nodeNotifier     *pubsub.Broker
	nodeListNotifier *pubsub.Broker
	runtimeNotifier  *pubsub.Broker
}

func (tb *tendermintBackend) RegisterEntity(ctx context.Context, sigEnt *entity.SignedEntity) error {
	tx := app.Tx{
		TxRegisterEntity: &app.TxRegisterEntity{
			Entity: *sigEnt,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, false); err != nil {
		return errors.Wrap(err, "registry: register entity failed")
	}

	return nil
}

func (tb *tendermintBackend) DeregisterEntity(ctx context.Context, sigTimestamp *signature.Signed) error {
	tx := app.Tx{
		TxDeregisterEntity: &app.TxDeregisterEntity{
			Timestamp: *sigTimestamp,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, false); err != nil {
		return errors.Wrap(err, "registry: deregister entity failed")
	}

	return nil
}

func (tb *tendermintBackend) GetEntity(ctx context.Context, id signature.PublicKey, height int64) (*entity.Entity, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Entity(ctx, id)
}

func (tb *tendermintBackend) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Entities(ctx)
}

func (tb *tendermintBackend) WatchEntities() (<-chan *api.EntityEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.EntityEvent)
	sub := tb.entityNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) RegisterNode(ctx context.Context, sigNode *node.SignedNode) error {
	tx := app.Tx{
		TxRegisterNode: &app.TxRegisterNode{
			Node: *sigNode,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, false); err != nil {
		return errors.Wrap(err, "registry: register node failed")
	}

	return nil
}

func (tb *tendermintBackend) UnfreezeNode(ctx context.Context, sigUnfreeze *api.SignedUnfreezeNode) error {
	tx := app.Tx{
		TxUnfreezeNode: &app.TxUnfreezeNode{
			UnfreezeNode: *sigUnfreeze,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "registry: unfreeze node failed")
	}

	return nil
}

func (tb *tendermintBackend) GetNode(ctx context.Context, id signature.PublicKey, height int64) (*node.Node, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Node(ctx, id)
}

func (tb *tendermintBackend) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Nodes(ctx)
}

func (tb *tendermintBackend) WatchNodes() (<-chan *api.NodeEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.NodeEvent)
	sub := tb.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) WatchNodeList() (<-chan *api.NodeList, *pubsub.Subscription) {
	typedCh := make(chan *api.NodeList)
	sub := tb.nodeListNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) RegisterRuntime(ctx context.Context, sigCon *api.SignedRuntime) error {
	if !tb.cfg.DebugAllowRuntimeRegistration {
		return api.ErrForbidden
	}

	tx := app.Tx{
		TxRegisterRuntime: &app.TxRegisterRuntime{
			Runtime: *sigCon,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, false); err != nil {
		return errors.Wrap(err, "registry: register runtime failed")
	}

	return nil
}

func (tb *tendermintBackend) GetRuntime(ctx context.Context, id signature.PublicKey, height int64) (*api.Runtime, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Runtime(ctx, id)
}

func (tb *tendermintBackend) WatchRuntimes() (<-chan *api.Runtime, *pubsub.Subscription) {
	typedCh := make(chan *api.Runtime)
	sub := tb.runtimeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (tb *tendermintBackend) GetNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	return tb.getNodeList(ctx, height)
}

func (tb *tendermintBackend) Cleanup() {
}

func (tb *tendermintBackend) GetRuntimes(ctx context.Context, height int64) ([]*api.Runtime, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Runtimes(ctx)
}

func (tb *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
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

	tb.onABCIEvents(ctx, events, ev.Block.Header.Height)
}

func (tb *tendermintBackend) onEventDataTx(ctx context.Context, tx tmtypes.EventDataTx) {
	tb.onABCIEvents(ctx, tx.Result.Events, tx.Height)
}

func (tb *tendermintBackend) onABCIEvents(ctx context.Context, events []abcitypes.Event, height int64) {
	for _, tmEv := range events {
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.KeyNodesExpired) {
				var nodes []*node.Node
				if err := cbor.Unmarshal(pair.GetValue(), &nodes); err != nil {
					tb.logger.Error("worker: failed to get nodes from tag",
						"err", err,
					)
				}

				for _, node := range nodes {
					tb.nodeNotifier.Broadcast(&api.NodeEvent{
						Node:           node,
						IsRegistration: false,
					})
				}
			} else if bytes.Equal(pair.GetKey(), app.KeyRuntimeRegistered) {
				var rt api.Runtime
				if err := cbor.Unmarshal(pair.GetValue(), &rt); err != nil {
					tb.logger.Error("worker: failed to get runtime from tag",
						"err", err,
					)
					continue
				}

				tb.runtimeNotifier.Broadcast(&rt)
			} else if bytes.Equal(pair.GetKey(), app.KeyEntityRegistered) {
				var ent entity.Entity
				if err := cbor.Unmarshal(pair.GetValue(), &ent); err != nil {
					tb.logger.Error("worker: failed to get entity from tag",
						"err", err,
					)
					continue
				}

				tb.entityNotifier.Broadcast(&api.EntityEvent{
					Entity:         &ent,
					IsRegistration: true,
				})
			} else if bytes.Equal(pair.GetKey(), app.KeyEntityDeregistered) {
				var dereg app.EntityDeregistration
				if err := cbor.Unmarshal(pair.GetValue(), &dereg); err != nil {
					tb.logger.Error("worker: failed to get entity deregistration from tag",
						"err", err,
					)
					continue
				}

				// Entity deregistration.
				tb.entityNotifier.Broadcast(&api.EntityEvent{
					Entity:         &dereg.Entity,
					IsRegistration: false,
				})

				// Node deregistrations.
				for _, node := range dereg.Nodes {
					nodeCopy := node
					tb.nodeNotifier.Broadcast(&api.NodeEvent{
						Node:           &nodeCopy,
						IsRegistration: false,
					})
				}
			} else if bytes.Equal(pair.GetKey(), app.KeyRegistryNodeListEpoch) {
				nl, err := tb.getNodeList(ctx, height)
				if err != nil {
					tb.logger.Error("worker: failed to get node list",
						"height", height,
						"err", err,
					)
					continue
				}
				tb.nodeListNotifier.Broadcast(nl)
			} else if bytes.Equal(pair.GetKey(), app.KeyNodeRegistered) {
				var n node.Node
				if err := cbor.Unmarshal(pair.GetValue(), &n); err != nil {
					tb.logger.Error("worker: failed to get node from tag",
						"err", err,
					)
					continue
				}

				tb.nodeNotifier.Broadcast(&api.NodeEvent{
					Node:           &n,
					IsRegistration: true,
				})
			}
		}
	}
}

func (tb *tendermintBackend) getNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	// Generate the nodelist.
	q, err := tb.querier.QueryAt(height)
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
func New(ctx context.Context, timeSource epochtime.Backend, service service.TendermintService, cfg *api.Config) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New(timeSource, cfg)
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		logger:           logging.GetLogger("registry/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		cfg:              cfg,
		entityNotifier:   pubsub.NewBroker(false),
		nodeNotifier:     pubsub.NewBroker(false),
		nodeListNotifier: pubsub.NewBroker(true),
	}
	tb.runtimeNotifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		wr := ch.In()
		runtimes, err := tb.GetRuntimes(ctx, 0)
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
