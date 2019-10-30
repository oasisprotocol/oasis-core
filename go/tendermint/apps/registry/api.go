package registry

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the entity registry application.
	TransactionTag byte = 0x01

	// AppName is the ABCI application name.
	AppName string = "200_registry"
)

var (
	// EventType is the ABCI event type for registry events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by
	// the registry application.
	QueryApp = api.QueryForApp(AppName)

	// KeyRuntimeRegistered is the ABCI event attribute for new
	// runtime registrations (value is the CBOR serialized runtime
	// descriptor).
	KeyRuntimeRegistered = []byte("runtime.registered")

	// KeyEntityRegistered is the ABCI event attribute for new entity
	// registrations (value is the CBOR serialized entity descriptor).
	KeyEntityRegistered = []byte("entity.registered")

	// KeyEntityDeregistered is the ABCI event attribute for entity
	// deregistrations (value is a CBOR serialized EntityDeregistration).
	KeyEntityDeregistered = []byte("entity.deregistered")

	// KeyNodeRegistered is the ABCI event attribute for new node
	// registrations (value is the CBOR serialized node descriptor).
	KeyNodeRegistered = []byte("nodes.registered")

	// KeyNodesExpired is the ABCI event attribute for node
	// deregistrations due to expiration (value is a CBOR serialized
	// vector of node descriptors).
	KeyNodesExpired = []byte("nodes.expired")

	// KeyNodeUnfrozen is the ABCI event attribute for when nodes
	// become unfrozen (value is CBOR serialized node ID).
	KeyNodeUnfrozen = []byte("nodes.unfrozen")

	// KeyRegistryNodeListEpoch is the ABCI event attribute for
	// registry epochs.
	KeyRegistryNodeListEpoch = []byte("nodes.epoch")
)

// Tx is a transaction to be accepted by the registry app.
type Tx struct {
	*TxRegisterEntity   `json:"RegisterEntity,omitempty"`
	*TxDeregisterEntity `json:"DeregisterEntity,omitempty"`
	*TxRegisterNode     `json:"RegisterNode,omitempty"`
	*TxUnfreezeNode     `json:"UnfreezeNode,omitempty"`

	*TxRegisterRuntime `json:"RegisterRuntime,omitempty"`
}

// TxRegisterEntity is a transaction for registering a new entity.
type TxRegisterEntity struct {
	Entity entity.SignedEntity `json:"entity"`
}

// TxDeregisterEntity is a transaction for deregistering an entity.
type TxDeregisterEntity struct {
	Timestamp signature.Signed `json:"timestamp"`
}

// TxRegisterNode is a transaction for registering a new node.
type TxRegisterNode struct {
	Node node.SignedNode `json:"node"`
}

// TxUnfreezeNode is a transaction for unfreezing a node.
type TxUnfreezeNode struct {
	UnfreezeNode registry.SignedUnfreezeNode `json:"unfreeze_node"`
}

// TxRegisterRuntime is a transaction for registering a new runtime.
type TxRegisterRuntime struct {
	Runtime registry.SignedRuntime `json:"runtime"`
}

// EntityDeregistration is an entity deregistration.
type EntityDeregistration struct {
	// Deregistered entity.
	Entity entity.Entity `json:"entity"`
}
