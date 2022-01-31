package committee

import (
	"context"

	keymanagerClientApi "github.com/oasisprotocol/oasis-core/go/keymanager/client/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

// Implements RuntimeHostHandlerFactory.
func (n *Node) GetRuntime() runtimeRegistry.Runtime {
	return n.Runtime
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(ctx, n.Runtime, host, n.Consensus)
}

type nodeEnvironment struct {
	n *Node
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetCurrentBlock(ctx context.Context) (*block.Block, error) {
	var blk *block.Block
	env.n.CrossNode.Lock()
	blk = env.n.CurrentBlock
	env.n.CrossNode.Unlock()
	return blk, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetKeyManagerClient(ctx context.Context) (keymanagerClientApi.Client, error) {
	return env.n.KeyManagerClient, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetTxPool(ctx context.Context) (txpool.TransactionPool, error) {
	return env.n.TxPool, nil
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.Runtime, n.Consensus)
}
