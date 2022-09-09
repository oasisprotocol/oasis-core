package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

// GetRuntime implements RuntimeHostHandlerFactory.
func (n *Node) GetRuntime() runtimeRegistry.Runtime {
	return n.Runtime
}

// NewRuntimeHostNotifier implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(ctx, n.Runtime, host, n.Consensus)
}

type nodeEnvironment struct {
	n *Node
}

// GetKeyManagerClient implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetKeyManagerClient(ctx context.Context) (runtimeKeymanager.Client, error) {
	return env.n.KeyManagerClient, nil
}

// GetTxPool implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetTxPool(ctx context.Context) (txpool.TransactionPool, error) {
	return env.n.TxPool, nil
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetNodeIdentity(ctx context.Context) (*identity.Identity, error) {
	return env.n.Identity, nil
}

// NewRuntimeHostHandler implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.Runtime, n.Consensus)
}
