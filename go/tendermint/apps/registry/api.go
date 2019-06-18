package registry

import (
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the entity registry application.
	TransactionTag byte = 0x01

	// AppName is the ABCI application name.
	AppName string = "999_registry"
)

var (
	// TagRuntimeRegistered is an ABCI transaction tag for new runtime
	// registrations (value is runtime id).
	TagRuntimeRegistered = []byte("registry.runtime.registered")

	// TagEntityRegistered is an ABCI transaction tag for new entity
	// registrations (value is entity id).
	TagEntityRegistered = []byte("registry.entity.registered")

	// TagNodesExpired is an ABCI transaction tag for node deregistrations
	// due to expiration (value is a CBOR serialized vector of node
	// descriptors).
	TagNodesExpired = []byte("registry.nodes.expired")

	// QueryApp is a query for filtering transactions processed by
	// the registry application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)

const (
	// QueryGetEntity is a path for GetEntity query.
	QueryGetEntity = AppName + "/entity"

	// QueryGetEntities is a path for GetEntities query.
	QueryGetEntities = AppName + "/entities"

	// QueryRegistryGetNode is a path for GetNode query.
	QueryGetNode = AppName + "/node"

	// QueryRegistryGetNodes is a path for GetNodes query.
	QueryGetNodes = AppName + "/nodes"

	// QueryRegistryGetRuntime is a path for GetRuntime query.
	QueryGetRuntime = AppName + "/runtime"

	// QueryRegistryGetRuntimes is a path for GetRuntimes query.
	QueryGetRuntimes = AppName + "/runtimes"
)

// Tx is a transaction to be accepted by the registry app.
type Tx struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxRegisterEntity   `codec:"RegisterEntity"`
	*TxDeregisterEntity `codec:"DeregisterEntity"`
	*TxRegisterNode     `codec:"RegisterNode"`

	*TxRegisterRuntime `codec:"RegisterRuntime"`
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
	_struct struct{} `codec:",omitempty"` // nolint

	*OutputRegisterEntity   `codec:"RegisterEntity"`
	*OutputDeregisterEntity `codec:"DeregisterEntity"`
	*OutputRegisterNode     `codec:"RegisterNode"`

	*OutputRegisterRuntime `codec:"RegisterRuntime"`
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
