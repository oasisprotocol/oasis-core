package keymanager

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

type workerEnvironment struct {
	w *Worker
}

// GetKeyManagerClient implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetKeyManagerClient() (runtimeKeymanager.Client, error) {
	return env.w.keyManagerClient, nil
}

// GetTxPool implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetTxPool() (txpool.TransactionPool, error) {
	return nil, fmt.Errorf("method not supported")
}

// GetNodeIdentity implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetNodeIdentity() (*identity.Identity, error) {
	return env.w.commonWorker.Identity, nil
}

// GetLightProvider implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetLightProvider() (consensusAPI.LightProvider, error) {
	return env.w.commonWorker.LightProvider, nil
}

// GetRuntimeRegistry implements RuntimeHostHandlerEnvironment.
func (env *workerEnvironment) GetRuntimeRegistry() runtimeRegistry.Registry {
	return env.w.commonWorker.RuntimeRegistry
}
