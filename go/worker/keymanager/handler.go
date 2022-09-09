package keymanager

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	committeeCommon "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// GetRuntime implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) GetRuntime() runtimeRegistry.Runtime {
	return w.runtime
}

// NewRuntimeHostNotifier implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) NewRuntimeHostNotifier(ctx context.Context, host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(ctx, w.runtime, host, w.commonWorker.Consensus)
}

type workerEnvironment struct {
	w *Worker

	kmCli *committeeCommon.KeyManagerClientWrapper
}

// GetKeyManagerClient implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetKeyManagerClient(ctx context.Context) (runtimeKeymanager.Client, error) {
	return env.kmCli, nil
}

// GetTxPool implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetTxPool(ctx context.Context) (txpool.TransactionPool, error) {
	return nil, fmt.Errorf("method not supported")
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetNodeIdentity(ctx context.Context) (*identity.Identity, error) {
	return env.w.commonWorker.Identity, nil
}

// NewRuntimeHostHandler implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) NewRuntimeHostHandler() protocol.Handler {
	kmCli := committeeCommon.NewKeyManagerClientWrapper(w.commonWorker.P2P, w.commonWorker.Consensus, w.logger)
	runtimeID := w.runtime.ID()
	kmCli.SetKeyManagerID(&runtimeID)

	return runtimeRegistry.NewRuntimeHostHandler(&workerEnvironment{
		w:     w,
		kmCli: kmCli,
	}, w.runtime, w.commonWorker.Consensus)
}
