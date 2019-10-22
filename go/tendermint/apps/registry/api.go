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
	// TagRuntimeRegistered is an ABCI tag for new runtime
	// registrations (value is runtime id).
	TagRuntimeRegistered = []byte("registry.runtime.registered")

	// TagEntityRegistered is an ABCI tag for new entity
	// registrations (value is entity id).
	TagEntityRegistered = []byte("registry.entity.registered")

	// TagNodesExpired is an ABCI tag for node deregistrations
	// due to expiration (value is a CBOR serialized vector of node
	// descriptors).
	TagNodesExpired = []byte("registry.nodes.expired")

	// TagRegistryNodeListEpoch is an ABCI tag for registry epochs.
	TagRegistryNodeListEpoch = []byte("registry.nodes.epoch")

	// QueryApp is a query for filtering events processed by
	// the registry application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)

// Tx is a transaction to be accepted by the registry app.
type Tx struct {
	*TxRegisterEntity   `json:"RegisterEntity,omitempty"`
	*TxDeregisterEntity `json:"DeregisterEntity,omitempty"`
	*TxRegisterNode     `json:"RegisterNode,omitempty"`

	*TxRegisterRuntime `json:"RegisterRuntime,omitempty"`
}

// TxRegisterEntity is a transaction for registering a new entity.
type TxRegisterEntity struct {
	Entity entity.SignedEntity
}

// TxDeregisterEntity is a transaction for deregistering an entity.
type TxDeregisterEntity struct {
	Timestamp signature.Signed
}

// TxRegisterNode is a transaction for registering a new node.
type TxRegisterNode struct {
	Node node.SignedNode
}

// TxRegisterRuntime is a transaction for registering a new runtime.
type TxRegisterRuntime struct {
	Runtime registry.SignedRuntime
}

// Output is an output of an registry app transaction.
type Output struct {
	*OutputRegisterEntity   `json:"RegisterEntity.omitempty"`
	*OutputDeregisterEntity `json:"DeregisterEntity,omitempty"`
	*OutputRegisterNode     `json:"RegisterNode,omitempty"`

	*OutputRegisterRuntime `json:"RegisterRuntime,omitempty"`
}

// OutputRegisterEntity is an output of registering a new entity.
type OutputRegisterEntity struct {
	// Registered entity.
	Entity entity.Entity
}

// OutputDeregisterEntity is an output of deregistering an entity.
type OutputDeregisterEntity struct {
	// Deregistered entity.
	Entity entity.Entity

	// Deregistered nodes (if any).
	Nodes []node.Node
}

// OutputRegisterNode is an output of registering a new node.
type OutputRegisterNode struct {
	// Registered node.
	Node node.Node
}

// OutputRegisterRuntime is an output of registering a new node.
type OutputRegisterRuntime struct {
	// Registered runtime.
	Runtime registry.Runtime
}
