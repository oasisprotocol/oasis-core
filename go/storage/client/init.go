package client

import (
	"context"
	"crypto/tls"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/oasis-core/go/common"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "client"

	// CfgDebugClientAddress is the address to connect to with the
	// storage client.
	CfgDebugClientAddress = "storage.debug.client.address"

	// CfgDebugClientCert is the path to the certificate file for grpc.
	CfgDebugClientCert = "storage.debug.client.certificate"
)

// In debug mode, we connect to the provided node and save it to the fake runtime.
const debugModeFakeRuntimeSeed = "oasis storage client debug runtime"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New creates a new storage client.
func New(
	ctx context.Context,
	namespace common.Namespace,
	ident *identity.Identity,
	schedulerBackend scheduler.Backend,
	registryBackend registry.Backend,
) (api.Backend, error) {
	logger := logging.GetLogger("storage/client")

	runtimeID, err := namespace.ToRuntimeID()
	if err != nil {
		return nil, err
	}

	if addr := viper.GetString(CfgDebugClientAddress); addr != "" && cmdFlags.DebugDontBlameOasis() {
		logger.Warn("Storage client in debug mode, connecting to provided client",
			"address", CfgDebugClientAddress,
		)

		var opts grpc.DialOption
		if certFile := viper.GetString(CfgDebugClientCert); certFile != "" {
			tlsConfig, err := cmnGrpc.NewClientTLSConfigFromFile(certFile, identity.CommonName)
			if err != nil {
				logger.Error("failed creating client tls config from file",
					"file", viper.GetString(certFile),
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

		conn, err := cmnGrpc.Dial(addr, opts)
		if err != nil {
			logger.Error("unable to dial debug client",
				"error", err,
			)
			return nil, err
		}
		client := api.NewStorageClient(conn)

		testRuntimeSigner := memorySigner.NewTestSigner(debugModeFakeRuntimeSeed)
		debugRuntimeID := testRuntimeSigner.Public()
		b := &storageClientBackend{
			ctx:            ctx,
			logger:         logger,
			debugRuntimeID: &debugRuntimeID,
		}
		state := &clientState{
			client: client,
			conn:   conn,
		}
		b.runtimeWatcher = newDebugWatcher(state)
		return b, nil
	}

	b := &storageClientBackend{
		ctx:            ctx,
		logger:         logger,
		runtimeWatcher: newWatcher(ctx, runtimeID, ident, schedulerBackend, registryBackend),
	}

	b.haltCtx, b.cancelFn = context.WithCancel(ctx)

	return b, nil
}

func init() {
	Flags.String(CfgDebugClientAddress, "", "Address of node to connect to with the storage client")
	Flags.String(CfgDebugClientCert, "", "Path to tls certificate for grpc")

	_ = Flags.MarkHidden(CfgDebugClientAddress)
	_ = Flags.MarkHidden(CfgDebugClientCert)

	_ = viper.BindPFlags(Flags)
}
