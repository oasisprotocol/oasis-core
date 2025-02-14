package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

// GetRuntime implements RuntimeHostHandlerFactory.
func (n *Node) GetRuntime() runtimeRegistry.Runtime {
	return n.Runtime
}

// NewRuntimeHostHandler implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() host.RuntimeHandler {
	return runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.Runtime, n.Consensus)
}

type nodeEnvironment struct {
	n *Node
}

// GetKeyManagerClient implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetKeyManagerClient() (runtimeKeymanager.Client, error) {
	return env.n.KeyManagerClient, nil
}

// GetTxPool implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetTxPool() (txpool.TransactionPool, error) {
	return env.n.TxPool, nil
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetNodeIdentity() (*identity.Identity, error) {
	return env.n.Identity, nil
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetLightClient() (consensusAPI.LightClient, error) {
	return env.n.LightClient, nil
}

// GetRuntimeRegistry implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetRuntimeRegistry() runtimeRegistry.Registry {
	return env.n.RuntimeRegistry
}
