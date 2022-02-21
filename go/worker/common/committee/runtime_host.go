package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	keymanagerP2P "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
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

type keymanagerClientWrapper struct {
	cli keymanagerP2P.Client
}

func (km *keymanagerClientWrapper) CallEnclave(ctx context.Context, data []byte) ([]byte, error) {
	rsp, pf, err := km.cli.CallEnclave(ctx, &keymanagerP2P.CallEnclaveRequest{
		Data: data,
	})
	if err != nil {
		return nil, err
	}
	// TODO: Support reporting peer feedback from the enclave.
	pf.RecordSuccess()
	return rsp.Data, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetKeyManagerClient(ctx context.Context) (runtimeKeymanager.Client, error) {
	return &keymanagerClientWrapper{cli: env.n.KeyManagerClient}, nil
}

// Implements RuntimeHostHandlerEnvironment.
func (env *nodeEnvironment) GetTxPool(ctx context.Context) (txpool.TransactionPool, error) {
	return env.n.TxPool, nil
}

// Implements RuntimeHostHandlerFactory.
func (n *Node) NewRuntimeHostHandler() protocol.Handler {
	return runtimeRegistry.NewRuntimeHostHandler(&nodeEnvironment{n}, n.Runtime, n.Consensus)
}
