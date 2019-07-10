package client

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

// In debug mode, we connect to the provided node and save it to the fake runtime.
const debugModeFakeRuntime = "12345678987654321"

// New creates a new storage client.
func New(ctx context.Context, schedulerBackend scheduler.Backend, registryBackend registry.Backend) (api.Backend, error) {
	logger := logging.GetLogger("storage/client")

	if viper.GetString(cfgDebugClientAddress) != "" {
		logger.Warn("Storage client in debug mode, connecting to provided client",
			"address", cfgDebugClientAddress,
		)

		var opts grpc.DialOption
		if viper.GetString(cfgDebugClientTLSCertFile) != "" {
			creds, err := credentials.NewClientTLSFromFile(viper.GetString(cfgDebugClientTLSCertFile), "ekiden-node")
			if err != nil {
				logger.Error("failed creating grpc tls client from file",
					"file", viper.GetString(cfgDebugClientTLSCertFile),
					"error", err,
				)
				return nil, err
			}
			opts = grpc.WithTransportCredentials(creds)
		} else {
			opts = grpc.WithInsecure()
		}

		conn, err := grpc.Dial(viper.GetString(cfgDebugClientAddress), opts)
		if err != nil {
			logger.Error("unable to dial debug client",
				"error", err,
			)
			return nil, err
		}
		client := storage.NewStorageClient(conn)

		debugRuntimePK := signature.NewTestPrivateKey(debugModeFakeRuntime)
		b := &storageClientBackend{
			logger:         logger,
			scheduler:      schedulerBackend,
			registry:       registryBackend,
			debugRuntimeID: debugRuntimePK.Public(),
			watcherState: &watcherState{
				initCh:                      make(chan struct{}),
				logger:                      logger,
				registeredStorageNodes:      []*node.Node{},
				perRuntimeScheduledNodeKeys: make(map[signature.MapKey][]signature.PublicKey),
				perRuntimeClientStates:      make(map[signature.MapKey][]*clientState),
			},
		}

		b.watcherState.perRuntimeClientStates[b.debugRuntimeID.ToMapKey()] = []*clientState{&clientState{
			client: client,
			conn:   conn,
		}}
		close(b.watcherState.initCh)

		return b, nil
	}

	b := &storageClientBackend{
		logger:    logger,
		scheduler: schedulerBackend,
		registry:  registryBackend,
		watcherState: &watcherState{
			initCh:                      make(chan struct{}),
			logger:                      logger,
			registeredStorageNodes:      []*node.Node{},
			perRuntimeScheduledNodeKeys: make(map[signature.MapKey][]signature.PublicKey),
			perRuntimeClientStates:      make(map[signature.MapKey][]*clientState),
		},
	}

	b.haltCtx, b.cancelFn = context.WithCancel(ctx)

	go b.watcher(ctx)

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgDebugClientAddress, "", "Address of node to connect to with the storage client")
		cmd.Flags().String(cfgDebugClientTLSCertFile, "", "Path to tls certificate for grpc")
	}

	for _, v := range []string{
		cfgDebugClientAddress,
		cfgDebugClientTLSCertFile,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
