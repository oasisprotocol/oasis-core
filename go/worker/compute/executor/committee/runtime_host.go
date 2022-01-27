package committee

import (
	"context"
	"fmt"

	keymanagerClientApi "github.com/oasisprotocol/oasis-core/go/keymanager/client/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	schedulingAPI "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
)

// Implements RuntimeHostHandlerFactory.
func (n *Node) GetRuntime() runtimeRegistry.Runtime {
	return n.commonNode.Runtime
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(ctx, n.commonNode.Runtime, host, n.commonNode.Consensus)
}

type nodeEnvironment struct {
	n *Node
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetCurrentBlock(ctx context.Context) (*block.Block, error) {
	var blk *block.Block
	env.n.commonNode.CrossNode.Lock()
	blk = env.n.commonNode.CurrentBlock
	env.n.commonNode.CrossNode.Unlock()
	return blk, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetKeyManagerClient(ctx context.Context) (keymanagerClientApi.Client, error) {
	return env.n.commonNode.KeyManagerClient, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetTxPool(ctx context.Context) (schedulingAPI.Scheduler, error) {
	env.n.schedulerMutex.Lock()
	defer env.n.schedulerMutex.Unlock()

	if env.n.scheduler == nil {
		return nil, fmt.Errorf("not available")
	}
	return env.n.scheduler, nil
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.commonNode.Runtime, n.commonNode.Consensus)
}
