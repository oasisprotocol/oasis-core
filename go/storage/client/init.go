package client

import (
	"context"
	"crypto/tls"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	commonGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/grpc/storage"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "client"

	// Address to connect to with the storage client.
	cfgDebugClientAddress = "storage.debug.client.address"

	// Path to certificate file for grpc.
	cfgDebugClientTLSCertFile = "storage.debug.client.tls"
)

// In debug mode, we connect to the provided node and save it to the fake runtime.
const debugModeFakeRuntimeSeed = "oasis storage client debug runtime"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New creates a new storage client.
func New(
	ctx context.Context,
	ident *identity.Identity,
	schedulerBackend scheduler.Backend,
	registryBackend registry.Backend,
) (api.Backend, error) {
	logger := logging.GetLogger("storage/client")

	if viper.GetString(cfgDebugClientAddress) != "" {
		logger.Warn("Storage client in debug mode, connecting to provided client",
			"address", cfgDebugClientAddress,
		)

		var opts grpc.DialOption
		if viper.GetString(cfgDebugClientTLSCertFile) != "" {
			tlsConfig, err := commonGrpc.NewClientTLSConfigFromFile(viper.GetString(cfgDebugClientTLSCertFile), identity.CommonName)
			if err != nil {
				logger.Error("failed creating client tls config from file",
					"file", viper.GetString(cfgDebugClientTLSCertFile),
					"error", err,
				)
				return nil, err
			}
			// Set client certificate.
			tlsConfig.Certificates = []tls.Certificate{*ident.TLSCertificate}
			opts = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
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

		testRuntimeSigner := memorySigner.NewTestSigner(debugModeFakeRuntimeSeed)
		b := &storageClientBackend{
			ctx:             ctx,
			initCh:          make(chan struct{}),
			logger:          logger,
			debugRuntimeID:  testRuntimeSigner.Public(),
			scheduler:       schedulerBackend,
			registry:        registryBackend,
			runtimeWatchers: make(map[signature.MapKey]storageWatcher),
			identity:        ident,
		}
		state := &clientState{
			client: client,
			conn:   conn,
		}
		close(b.initCh)
		b.runtimeWatchers[b.debugRuntimeID.ToMapKey()] = newDebugWatcher(state)
		return b, nil
	}

	b := &storageClientBackend{
		ctx:             ctx,
		initCh:          make(chan struct{}),
		logger:          logger,
		scheduler:       schedulerBackend,
		registry:        registryBackend,
		runtimeWatchers: make(map[signature.MapKey]storageWatcher),
		identity:        ident,
	}

	b.haltCtx, b.cancelFn = context.WithCancel(ctx)

	return b, nil
}

func init() {
	Flags.String(cfgDebugClientAddress, "", "Address of node to connect to with the storage client")
	Flags.String(cfgDebugClientTLSCertFile, "", "Path to tls certificate for grpc")

	_ = viper.BindPFlags(Flags)
}
