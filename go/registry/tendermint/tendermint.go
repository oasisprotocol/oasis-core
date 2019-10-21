// Package tendermint implements the tendermint backed registry backend.
package tendermint

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
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

func (tb *tendermintBackend) GetEntity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	q, err := tb.querier.QueryAt(0)
	if err != nil {
		return nil, err
	}

	return q.Entity(ctx, id)
}

func (tb *tendermintBackend) GetEntities(ctx context.Context) ([]*entity.Entity, error) {
	q, err := tb.querier.QueryAt(0)
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

func (tb *tendermintBackend) GetNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	q, err := tb.querier.QueryAt(0)
	if err != nil {
		return nil, err
	}

	return q.Node(ctx, id)
}

func (tb *tendermintBackend) GetNodes(ctx context.Context) ([]*node.Node, error) {
	q, err := tb.querier.QueryAt(0)
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

func (tb *tendermintBackend) GetRuntime(ctx context.Context, id signature.PublicKey) (*api.Runtime, error) {
	q, err := tb.querier.QueryAt(0)
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
			tb.onEventDataTx(ev)
		default:
		}
	}
}

func (tb *tendermintBackend) onEventDataNewBlock(ctx context.Context, ev tmtypes.EventDataNewBlock) {
	events := ev.ResultBeginBlock.GetEvents()
	events = append(events, ev.ResultEndBlock.GetEvents()...)
	for _, tmEv := range events {
		if tmEv.GetType() != tmapi.EventTypeOasis {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			if bytes.Equal(pair.GetKey(), app.TagNodesExpired) {
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
			} else if bytes.Equal(pair.GetKey(), app.TagRuntimeRegistered) {
				var id signature.PublicKey
				if err := id.UnmarshalBinary(pair.GetValue()); err != nil {
					tb.logger.Error("worker: failed to get runtime from tag",
						"err", err,
					)
					continue
				}

				rt, err := tb.GetRuntime(ctx, id)
				if err != nil {
					tb.logger.Error("worker: failed to get runtime from registry",
						"err", err,
						"runtime", id,
					)
					continue
				}

				tb.runtimeNotifier.Broadcast(rt)
			} else if bytes.Equal(pair.GetKey(), app.TagEntityRegistered) {
				var id signature.PublicKey
				if err := id.UnmarshalBinary(pair.GetValue()); err != nil {
					tb.logger.Error("worker: failed to get entity from tag",
						"err", err,
					)
					continue
				}

				ent, err := tb.GetEntity(ctx, id)
				if err != nil {
					tb.logger.Error("worker: failed to get entity from registry",
						"err", err,
						"entity", id,
					)
					continue
				}

				tb.entityNotifier.Broadcast(&api.EntityEvent{
					Entity:         ent,
					IsRegistration: true,
				})
			} else if bytes.Equal(pair.GetKey(), app.TagRegistryNodeListEpoch) {
				nl, err := tb.getNodeList(ctx, ev.Block.Header.Height)
				if err != nil {
					tb.logger.Error("worker: failed to get node list",
						"height", ev.Block.Header.Height,
						"err", err,
					)
					continue
				}
				tb.nodeListNotifier.Broadcast(nl)
			}
		}
	}
}

func (tb *tendermintBackend) onEventDataTx(tx tmtypes.EventDataTx) {
	output := &app.Output{}
	if err := cbor.Unmarshal(tx.Result.GetData(), output); err != nil {
		tb.logger.Error("worker: malformed transaction output",
			"tx", hex.EncodeToString(tx.Result.GetData()),
		)
		return
	}

	if re := output.OutputRegisterEntity; re != nil {
		// Entity registration.
		tb.entityNotifier.Broadcast(&api.EntityEvent{
			Entity:         &re.Entity,
			IsRegistration: true,
		})
	} else if de := output.OutputDeregisterEntity; de != nil {
		// Entity deregistration.
		tb.entityNotifier.Broadcast(&api.EntityEvent{
			Entity:         &de.Entity,
			IsRegistration: false,
		})

		// Node deregistrations.
		for _, node := range output.Nodes {
			nodeCopy := node
			tb.nodeNotifier.Broadcast(&api.NodeEvent{
				Node:           &nodeCopy,
				IsRegistration: false,
			})
		}
	} else if rn := output.OutputRegisterNode; rn != nil {
		// Node registration.
		tb.nodeNotifier.Broadcast(&api.NodeEvent{
			Node:           &rn.Node,
			IsRegistration: true,
		})
	} else if rc := output.OutputRegisterRuntime; rc != nil {
		// Runtime registration.
		tb.runtimeNotifier.Broadcast(&rc.Runtime)
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
