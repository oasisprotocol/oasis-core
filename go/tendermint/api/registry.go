package api

import (
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
)

const (
	// RegistryTransactionTag is a unique byte used to identify
	// transactions for the entity registry application.
	RegistryTransactionTag byte = 0x01

	// RegistryAppName is the ABCI application name.
	RegistryAppName string = "registry"
)

var (
	// TagRegistryEntityRegistered is an ABCI transaction tag for new entity
	// registrations (value is entity id).
	TagRegistryEntityRegistered = []byte("registry.entity.registered")
	// TagRegistryEntityDeregistered is an ABCI transaction tag for new
	// entity registrations (value is entity id).
	TagRegistryEntityDeregistered = []byte("registry.entity.deregistered")

	// TagRegistryNodeRegistered is an ABCI transaction tag for new node
	// registrations (value is node id).
	TagRegistryNodeRegistered = []byte("registry.node.registered")

	// TagRegistryContractRegistered is an ABCI transaction tag for new
	// contract registrations (value is contract id).
	TagRegistryContractRegistered = []byte("registry.contract.registered")
)

const (
	// QueryRegistryGetEntity is a path for GetEntity query.
	QueryRegistryGetEntity = "registry/entity"
	// QueryRegistryGetNode is a path for GetNode query.
	QueryRegistryGetNode = "registry/node"
	// QueryRegistryGetContract is a path for GetContract query.
	QueryRegistryGetContract = "registry/contract"
)

var (
	// QueryRegistryApp is a query for filtering transactions processed by
	// the registry application.
	QueryRegistryApp = QueryForEvent(TagApplication, []byte(RegistryAppName))
)

// TxRegistry is a transaction to be accepted by the registry app.
type TxRegistry struct {
	_struct struct{} `codec:",omitempty"`

	*TxRegisterEntity   `codec:"RegisterEntity"`
	*TxDeregisterEntity `codec:"DeregisterEntity"`
	*TxRegisterNode     `codec:"RegisterNode"`

	*TxRegisterContract `codec:"RegisterContract"`
}

// TxRegisterEntity is a transaction for registering a new entity.
type TxRegisterEntity struct {
	Entity    entity.Entity
	Signature signature.Signature
}

// TxDeregisterEntity is a transaction for deregistering an entity.
type TxDeregisterEntity struct {
	ID        signature.PublicKey
	Signature signature.Signature
}

// TxRegisterNode is a transaction for registering a new node.
type TxRegisterNode struct {
	Node      node.Node
	Signature signature.Signature
}

// TxRegisterContract is a transaction for registering a new contract.
type TxRegisterContract struct {
	Contract  contract.Contract
	Signature signature.Signature
}

// OutputRegistry is an output of an registry app transaction.
type OutputRegistry struct {
	_struct struct{} `codec:",omitempty"`

	*OutputRegisterEntity   `codec:"RegisterEntity"`
	*OutputDeregisterEntity `codec:"DeregisterEntity"`
	*OutputRegisterNode     `codec:"RegisterNode"`

	*OutputRegisterContract `codec:"RegisterContract"`
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

// OutputRegisterContract is an output of registering a new node.
type OutputRegisterContract struct {
	// Registered contract.
	Contract contract.Contract
}

// QueryGetByIDRequest is a request for fetching things by ids.
type QueryGetByIDRequest struct {
	ID signature.PublicKey
}
