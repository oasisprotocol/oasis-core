package registry

import (
	"encoding/hex"

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
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// TendermintClientEntityRegistry is a Tendermint-based registry entity backend.
type TendermintClientEntityRegistry struct {
	logger *logging.Logger

	client tmcli.Client

	entityNotifier *pubsub.Broker
	nodeNotifier   *pubsub.Broker
}

// RegisterEntity registers and or updates an entity with the registry.
//
// The signature should be made using RegisterEntitySignatureContext.
func (r *TendermintClientEntityRegistry) RegisterEntity(ent *entity.Entity, sig *signature.Signature) error {
	tx := api.TxRegistry{
		TxRegisterEntity: &api.TxRegisterEntity{
			Entity:    *ent,
			Signature: *sig,
		},
	}

	if err := api.BroadcastTx(r.client, api.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register entity failed")
	}

	return nil
}

// DeregisterEntity deregisters an entity.
//
// The signature should be made using DeregisterEntitySignatureContext.
func (r *TendermintClientEntityRegistry) DeregisterEntity(id signature.PublicKey, sig *signature.Signature) error {
	tx := api.TxRegistry{
		TxDeregisterEntity: &api.TxDeregisterEntity{
			ID:        id,
			Signature: *sig,
		},
	}

	if err := api.BroadcastTx(r.client, api.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: deregister entity failed")
	}

	return nil
}

// GetEntity gets an entity by ID.
func (r *TendermintClientEntityRegistry) GetEntity(id signature.PublicKey) (*entity.Entity, error) {
	query := api.QueryGetByIDRequest{
		ID: id,
	}

	response, err := api.Query(r.client, api.QueryRegistryGetEntity, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get entity query failed")
	}

	var ent entity.Entity
	if err := cbor.Unmarshal(response, &ent); err != nil {
		return nil, errors.Wrap(err, "registry: get entity malformed response")
	}

	return &ent, nil
}

// GetEntities gets a list of all registered entities.
func (r *TendermintClientEntityRegistry) GetEntities() []*entity.Entity {
	// TODO: Need support for range queries on previous versions of the tree.
	return nil
}

// WatchEntities returns a channel that produces a stream of
// EntityEvent on entity registration changes.
func (r *TendermintClientEntityRegistry) WatchEntities() (<-chan *EntityEvent, *pubsub.Subscription) {
	return subscribeTypedEntityEvent(r.entityNotifier)
}

// RegisterNode registers and or updates a node with the registry.
//
// The signature should be made using RegisterNodeSignatureContext.
func (r *TendermintClientEntityRegistry) RegisterNode(node *node.Node, sig *signature.Signature) error {
	tx := api.TxRegistry{
		TxRegisterNode: &api.TxRegisterNode{
			Node:      *node,
			Signature: *sig,
		},
	}

	if err := api.BroadcastTx(r.client, api.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register node failed")
	}

	return nil
}

// GetNode gets a node by ID.
func (r *TendermintClientEntityRegistry) GetNode(id signature.PublicKey) (*node.Node, error) {
	query := api.QueryGetByIDRequest{
		ID: id,
	}

	response, err := api.Query(r.client, api.QueryRegistryGetNode, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get node query failed")
	}

	var node node.Node
	if err := cbor.Unmarshal(response, &node); err != nil {
		return nil, errors.Wrap(err, "registry: get node malformed response")
	}

	return &node, nil
}

// GetNodes gets a list of all registered nodes.
func (r *TendermintClientEntityRegistry) GetNodes() []*node.Node {
	// TODO: Need support for range queries on previous versions of the tree.
	return nil
}

// GetNodesForEntity gets a list of nodes registered to an entity ID.
func (r *TendermintClientEntityRegistry) GetNodesForEntity(id signature.PublicKey) []*node.Node {
	// TODO: Need support for range queries on previous versions of the tree.
	return nil
}

// WatchNodes returns a channel that produces a stream of
// NodeEvent on node registration changes.
func (r *TendermintClientEntityRegistry) WatchNodes() (<-chan *NodeEvent, *pubsub.Subscription) {
	return subscribeTypedNodeEvent(r.nodeNotifier)
}

// WatchNodeList returns a channel that produces a stream of NodeList.
// Upon subscription, the node list for the current epoch will be sent
// immediately if available.
//
// Each node list will be sorted by node ID in lexographically ascending
// order.
func (r *TendermintClientEntityRegistry) WatchNodeList() (<-chan *NodeList, *pubsub.Subscription) {
	// TODO: Need Tendermint-based epochs first.
	return nil, nil
}

func (r *TendermintClientEntityRegistry) worker() {
	// Subscribe to transactions which modify entities and nodes.
	ctx := context.Background()
	txChannel := make(chan interface{})

	if err := r.client.Subscribe(ctx, "ekiden-registry-worker", api.QueryRegistryApp, txChannel); err != nil {
		panic("worker: failed to subscribe")
	}
	defer r.client.Unsubscribe(ctx, "ekiden-registry-worker", api.QueryRegistryApp)

	// Process transactions and emit notifications for our subscribers.
	for {
		rawTx, ok := <-txChannel
		if !ok {
			r.logger.Error("worker: terminating")
			return
		}

		// Extract output information from transaction.
		tx := rawTx.(tmtypes.EventDataTx)

		output := &api.OutputRegistry{}
		if err := cbor.Unmarshal(tx.Result.GetData(), output); err != nil {
			r.logger.Error("worker: malformed transaction output",
				"tx", hex.EncodeToString(tx.Result.GetData()),
			)
			continue
		}

		if re := output.OutputRegisterEntity; re != nil {
			// Entity registration.
			r.entityNotifier.Broadcast(&EntityEvent{
				Entity:         &re.Entity,
				IsRegistration: true,
			})
		} else if de := output.OutputDeregisterEntity; de != nil {
			// Entity deregistration.
			r.entityNotifier.Broadcast(&EntityEvent{
				Entity:         &de.Entity,
				IsRegistration: false,
			})

			// Node deregistrations.
			for _, node := range output.Nodes {
				r.nodeNotifier.Broadcast(&NodeEvent{
					Node:           &node,
					IsRegistration: false,
				})
			}
		} else if rn := output.OutputRegisterNode; rn != nil {
			// Node registration.
			r.nodeNotifier.Broadcast(&NodeEvent{
				Node:           &rn.Node,
				IsRegistration: true,
			})
		}
	}
}

// NewTendermintClientEntityRegistry constructs a new TendermintClientEntityRegistry instance.
func NewTendermintClientEntityRegistry(service service.TendermintService) EntityRegistry {
	r := &TendermintClientEntityRegistry{
		logger:         logging.GetLogger("TendermintClientEntityRegistry"),
		client:         service.GetClient(),
		entityNotifier: pubsub.NewBroker(false),
		nodeNotifier:   pubsub.NewBroker(false),
	}

	go r.worker()

	return r
}

// TendermintClientContractRegistry is a Tendermint-based registry entity backend.
type TendermintClientContractRegistry struct {
	logger *logging.Logger

	client tmcli.Client

	contractNotifier *pubsub.Broker
}

// RegisterContract registers a contract.
func (r *TendermintClientContractRegistry) RegisterContract(con *contract.Contract, sig *signature.Signature) error {
	tx := api.TxRegistry{
		TxRegisterContract: &api.TxRegisterContract{
			Contract:  *con,
			Signature: *sig,
		},
	}

	if err := api.BroadcastTx(r.client, api.RegistryTransactionTag, tx); err != nil {
		return errors.Wrap(err, "registry: register contract failed")
	}

	return nil
}

// GetContract gets a contract by ID.
func (r *TendermintClientContractRegistry) GetContract(id signature.PublicKey) (*contract.Contract, error) {
	query := api.QueryGetByIDRequest{
		ID: id,
	}

	response, err := api.Query(r.client, api.QueryRegistryGetContract, query)
	if err != nil {
		return nil, errors.Wrap(err, "registry: get contract query failed")
	}

	var con contract.Contract
	if err := cbor.Unmarshal(response, &con); err != nil {
		return nil, errors.Wrap(err, "registry: get contract malformed response")
	}

	return &con, nil
}

// WatchContracts returns a stream of Contract.  Upon subscription,
// all contracts will be sent immediately.
func (r *TendermintClientContractRegistry) WatchContracts() (<-chan *contract.Contract, *pubsub.Subscription) {
	return subscribeTypedContract(r.contractNotifier)
}

func (r *TendermintClientContractRegistry) worker() {
	// Subscribe to transactions which modify contracts.
	ctx := context.Background()
	txChannel := make(chan interface{})

	if err := r.client.Subscribe(ctx, "ekiden-registry-worker", api.QueryRegistryApp, txChannel); err != nil {
		panic("worker: failed to subscribe")
	}
	defer r.client.Unsubscribe(ctx, "ekiden-registry-worker", api.QueryRegistryApp)

	// Process transactions and emit notifications for our subscribers.
	for {
		rawTx, ok := <-txChannel
		if !ok {
			r.logger.Error("worker: terminating")
			return
		}

		// Extract output information from transaction.
		tx := rawTx.(tmtypes.EventDataTx)

		output := &api.OutputRegistry{}
		if err := cbor.Unmarshal(tx.Result.GetData(), output); err != nil {
			r.logger.Error("worker: malformed transaction output",
				"tx", hex.EncodeToString(tx.Result.GetData()),
			)
			continue
		}

		if rc := output.OutputRegisterContract; rc != nil {
			// Contract registration.
			r.contractNotifier.Broadcast(&rc.Contract)
		}
	}
}

// NewTendermintClientContractRegistry constructs a new TendermintClientContractRegistry instance.
func NewTendermintClientContractRegistry(service service.TendermintService) ContractRegistry {
	r := &TendermintClientContractRegistry{
		logger:           logging.GetLogger("TendermintClientContractRegistry"),
		client:           service.GetClient(),
		contractNotifier: pubsub.NewBroker(false),
	}

	// TODO: Make the contractNotifier fetch all contracts once we have GetContracts.

	go r.worker()

	return r
}
