// Package tendermint implements the tendermint backed registry backend.
package tendermint

import (
	"encoding/hex"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmcli "github.com/tendermint/tendermint/rpc/client"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/registry/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = "tendermint"

var _ api.Backend = (*tendermintBackend)(nil)

type tendermintBackend struct {
	logger *logging.Logger

	client tmcli.Client

	entityNotifier   *pubsub.Broker
	nodeNotifier     *pubsub.Broker
	contractNotifier *pubsub.Broker
}

func (r *tendermintBackend) RegisterEntity(ctx context.Context, ent *entity.Entity, sig *signature.Signature) error {
	tx := tmapi.TxRegistry{
		TxRegisterEntity: &tmapi.TxRegisterEntity{
			Entity:    *ent,
			Signature: *sig,
		},
	}

	if err := tmapi.BroadcastTx(r.client, tmapi.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register entity failed")
	}

	return nil
}

func (r *tendermintBackend) DeregisterEntity(ctx context.Context, id signature.PublicKey, sig *signature.Signature) error {
	tx := tmapi.TxRegistry{
		TxDeregisterEntity: &tmapi.TxDeregisterEntity{
			ID:        id,
			Signature: *sig,
		},
	}

	if err := tmapi.BroadcastTx(r.client, tmapi.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: deregister entity failed")
	}

	return nil
}

func (r *tendermintBackend) GetEntity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetEntity, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get entity query failed")
	}

	var ent entity.Entity
	if err := cbor.Unmarshal(response, &ent); err != nil {
		return nil, errors.Wrap(err, "registry: get entity malformed response")
	}

	return &ent, nil
}

func (r *tendermintBackend) GetEntities(ctx context.Context) ([]*entity.Entity, error) {
	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetEntities, nil)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get entities query failed")
	}

	var ents []*entity.Entity
	if err := cbor.Unmarshal(response, &ents); err != nil {
		return nil, errors.Wrap(err, "registry: get entities malformed response")
	}

	return ents, nil
}

func (r *tendermintBackend) WatchEntities() (<-chan *api.EntityEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.EntityEvent)
	sub := r.entityNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *tendermintBackend) RegisterNode(ctx context.Context, node *node.Node, sig *signature.Signature) error {
	tx := tmapi.TxRegistry{
		TxRegisterNode: &tmapi.TxRegisterNode{
			Node:      *node,
			Signature: *sig,
		},
	}

	if err := tmapi.BroadcastTx(r.client, tmapi.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register node failed")
	}

	return nil
}

func (r *tendermintBackend) GetNode(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetNode, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get node query failed")
	}

	var node node.Node
	if err := cbor.Unmarshal(response, &node); err != nil {
		return nil, errors.Wrap(err, "registry: get node malformed response")
	}

	return &node, nil
}

func (r *tendermintBackend) GetNodes(ctx context.Context) ([]*node.Node, error) {
	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetNodes, nil)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get nodes query failed")
	}

	var nodes []*node.Node
	if err := cbor.Unmarshal(response, &nodes); err != nil {
		return nil, errors.Wrap(err, "registry: get nodes malformed response")
	}

	return nodes, nil
}

func (r *tendermintBackend) GetNodesForEntity(ctx context.Context, id signature.PublicKey) []*node.Node {
	// TODO: Need support for range queries on previous versions of the tree.
	return nil
}

func (r *tendermintBackend) WatchNodes() (<-chan *api.NodeEvent, *pubsub.Subscription) {
	typedCh := make(chan *api.NodeEvent)
	sub := r.nodeNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *tendermintBackend) WatchNodeList() (<-chan *api.NodeList, *pubsub.Subscription) {
	// TODO: Need Tendermint-based epochs first.
	return nil, nil
}

func (r *tendermintBackend) RegisterContract(ctx context.Context, con *contract.Contract, sig *signature.Signature) error {
	tx := tmapi.TxRegistry{
		TxRegisterContract: &tmapi.TxRegisterContract{
			Contract:  *con,
			Signature: *sig,
		},
	}

	if err := tmapi.BroadcastTx(r.client, tmapi.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register contract failed")
	}

	return nil
}

func (r *tendermintBackend) GetContract(ctx context.Context, id signature.PublicKey) (*contract.Contract, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetContract, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get contract query failed")
	}

	var con contract.Contract
	if err := cbor.Unmarshal(response, &con); err != nil {
		return nil, errors.Wrap(err, "registry: get contract malformed response")
	}

	return &con, nil
}

func (r *tendermintBackend) WatchContracts() (<-chan *contract.Contract, *pubsub.Subscription) {
	typedCh := make(chan *contract.Contract)
	sub := r.contractNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (r *tendermintBackend) getContracts(ctx context.Context) ([]*contract.Contract, error) {
	response, err := tmapi.Query(r.client, tmapi.QueryRegistryGetContracts, nil)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get contracts query failed")
	}

	var contracts []*contract.Contract
	if err := cbor.Unmarshal(response, &contracts); err != nil {
		return nil, errors.Wrap(err, "registry: get contracts malformed response")
	}

	return contracts, nil
}

func (r *tendermintBackend) worker() {
	// Subscribe to transactions which modify state.
	ctx := context.Background()
	txChannel := make(chan interface{})

	if err := r.client.Subscribe(ctx, "ekiden-registry-worker", tmapi.QueryRegistryApp, txChannel); err != nil {
		panic("worker: failed to subscribe")
	}
	defer r.client.Unsubscribe(ctx, "ekiden-registry-worker", tmapi.QueryRegistryApp) // nolint: errcheck

	// Process transactions and emit notifications for our subscribers.
	for {
		rawTx, ok := <-txChannel
		if !ok {
			r.logger.Error("worker: terminating")
			return
		}

		// Extract output information from transaction.
		tx := rawTx.(tmtypes.EventDataTx)

		output := &tmapi.OutputRegistry{}
		if err := cbor.Unmarshal(tx.Result.GetData(), output); err != nil {
			r.logger.Error("worker: malformed transaction output",
				"tx", hex.EncodeToString(tx.Result.GetData()),
			)
			continue
		}

		if re := output.OutputRegisterEntity; re != nil {
			// Entity registration.
			r.entityNotifier.Broadcast(&api.EntityEvent{
				Entity:         &re.Entity,
				IsRegistration: true,
			})
		} else if de := output.OutputDeregisterEntity; de != nil {
			// Entity deregistration.
			r.entityNotifier.Broadcast(&api.EntityEvent{
				Entity:         &de.Entity,
				IsRegistration: false,
			})

			// Node deregistrations.
			for _, node := range output.Nodes {
				r.nodeNotifier.Broadcast(&api.NodeEvent{
					Node:           &node,
					IsRegistration: false,
				})
			}
		} else if rn := output.OutputRegisterNode; rn != nil {
			// Node registration.
			r.nodeNotifier.Broadcast(&api.NodeEvent{
				Node:           &rn.Node,
				IsRegistration: true,
			})
		} else if rc := output.OutputRegisterContract; rc != nil {
			// Contract registration.
			r.contractNotifier.Broadcast(&rc.Contract)
		}
	}
}

// New constructs a new tendermint backed registry Backend instance.
func New(service service.TendermintService) api.Backend {
	r := &tendermintBackend{
		logger:         logging.GetLogger("registry/tendermint"),
		client:         service.GetClient(),
		entityNotifier: pubsub.NewBroker(false),
		nodeNotifier:   pubsub.NewBroker(false),
	}
	r.contractNotifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		wr := ch.In()
		contracts, err := r.getContracts(context.Background())
		if err != nil {
			r.logger.Error("contract notifier: unable to get a list of contracts",
				"err", err,
			)
			return
		}

		for _, v := range contracts {
			wr <- v
		}
	})

	go r.worker()

	return r
}
