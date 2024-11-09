package keymanager

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
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
func (w *Worker) NewRuntimeHostNotifier(host host.Runtime) protocol.Notifier {
	return runtimeRegistry.NewRuntimeHostNotifier(w.runtime, host, w.commonWorker.Consensus)
}

type workerEnvironment struct {
	w *Worker

	kmCli *committeeCommon.KeyManagerClientWrapper
}

// GetKeyManagerClient implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetKeyManagerClient() (runtimeKeymanager.Client, error) {
	return env.kmCli, nil
}

// GetTxPool implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetTxPool() (txpool.TransactionPool, error) {
	return nil, fmt.Errorf("method not supported")
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetNodeIdentity() (*identity.Identity, error) {
	return env.w.commonWorker.Identity, nil
}

// GetIdentity implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetLightClient() (consensusAPI.LightClient, error) {
	if env.w.commonWorker.LightClient == nil {
		return nil, fmt.Errorf("no light client available")
	}
	return env.w.commonWorker.LightClient, nil
}

// GetRuntimeRegistry implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetRuntimeRegistry() runtimeRegistry.Registry {
	return env.w.commonWorker.RuntimeRegistry
}

// NewRuntimeHostHandler implements workerCommon.RuntimeHostHandlerFactory.
func (w *Worker) NewRuntimeHostHandler() host.RuntimeHandler {
	kmCli := committeeCommon.NewKeyManagerClientWrapper(w.commonWorker.P2P, w.commonWorker.Consensus, w.commonWorker.ChainContext, w.logger)
	runtimeID := w.runtime.ID()
	kmCli.SetKeyManagerID(&runtimeID)

	return runtimeRegistry.NewRuntimeHostHandler(&workerEnvironment{
		w:     w,
		kmCli: kmCli,
	}, w.runtime, w.commonWorker.Consensus)
}
