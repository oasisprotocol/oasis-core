// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	// CfgEnabled enables the key manager worker.
	CfgEnabled = "worker.keymanager.enabled"

	// CfgRuntimeID configures the runtime ID.
	CfgRuntimeID = "worker.keymanager.runtime.id"
	// CfgMayGenerate allows the enclave to generate a master secret.
	CfgMayGenerate = "worker.keymanager.may_generate"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgEnabled)
}

// New constructs a new key manager worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	ias ias.Endpoint,
	r *registration.Worker,
	backend api.Backend,
) (*Worker, error) {
	ctx, cancelFn := context.WithCancel(context.Background())

	w := &Worker{
		logger:       logging.GetLogger("worker/keymanager"),
		ctx:          ctx,
		cancelCtx:    cancelFn,
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		initTickerCh: nil,
		commonWorker: commonWorker,
		backend:      backend,
		grpcPolicy:   policy.NewDynamicRuntimePolicyChecker(enclaverpc.ServiceName, commonWorker.GrpcPolicyWatcher),
		enabled:      Enabled(),
		mayGenerate:  viper.GetBool(CfgMayGenerate),
	}

	if w.enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for key manager worker")
		}

		var runtimeID common.Namespace
		if err := runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to parse runtime ID: %w", err)
		}

		// Create local storage for the key manager.
		path, err := runtimeRegistry.EnsureRuntimeStateDir(dataDir, runtimeID)
		if err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to ensure runtime state directory: %w", err)
		}
		localStorage, err := localstorage.New(path, runtimeRegistry.LocalStorageFile, runtimeID)
		if err != nil {
			return nil, fmt.Errorf("worker/keymanager: cannot create local storage: %w", err)
		}

		w.roleProvider, err = r.NewRuntimeRoleProvider(node.RoleKeyManager, runtimeID)
		if err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to create role provider: %w", err)
		}

		w.runtime, err = commonWorker.RuntimeRegistry.NewUnmanagedRuntime(ctx, runtimeID)
		if err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to create runtime registry entry: %w", err)
		}

		w.runtimeHostHandler = newHostHandler(w, commonWorker, localStorage)

		// Prepare the runtime host node helpers.
		w.RuntimeHostNode, err = runtimeRegistry.NewRuntimeHostNode(w)
		if err != nil {
			return nil, fmt.Errorf("worker/keymanager: failed to create runtime host helpers: %w", err)
		}

		// Register the Keymanager EnclaveRPC transport gRPC service.
		enclaverpc.RegisterService(w.commonWorker.Grpc.Server(), w)
	}

	return w, nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable key manager worker")

	Flags.String(CfgRuntimeID, "", "Key manager Runtime ID")
	Flags.Bool(CfgMayGenerate, false, "Key manager may generate new master secret")

	_ = viper.BindPFlags(Flags)
}
