// Package grpc implements a gRPC sentry worker.
package grpc

import (
	"context"
	tlsPkg "crypto/tls"
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/proxy"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	sentry "github.com/oasisprotocol/oasis-core/go/sentry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

const (
	// CfgEnabled enables the sentry grpc worker.
	CfgEnabled = "worker.sentry.grpc.enabled"

	// CfgUpstreamAddress is the grpc address of the upstream node.
	CfgUpstreamAddress = "worker.sentry.grpc.upstream.address"
	// CfgUpstreamID is the node ID of the upstream node.
	CfgUpstreamID = "worker.sentry.grpc.upstream.id"

	// CfgClientAddresses are addresses on which the gRPC endpoint is reachable.
	CfgClientAddresses = "worker.sentry.grpc.client.address"
	// CfgClientPort is the sentry node's client port.
	CfgClientPort = "worker.sentry.grpc.client.port"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// GetNodeAddresses returns configured sentry node addresses.
func GetNodeAddresses() ([]node.Address, error) {
	clientAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(CfgClientAddresses))
	if err != nil {
		return nil, err
	}
	return clientAddresses, nil
}

func initConnection(ctx context.Context, logger *logging.Logger, ident *identity.Identity, backend sentry.LocalBackend) (*grpc.ClientConn, error) {
	var err error

	addr := viper.GetString(CfgUpstreamAddress)

	upstreamAddrs, err := configparser.ParseAddressList([]string{addr})
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %s: %w", addr, err)
	}

	upstreamNodeIDRaw := viper.GetString(CfgUpstreamID)
	var upstreamNodeID signature.PublicKey
	err = upstreamNodeID.UnmarshalText([]byte(upstreamNodeIDRaw))
	if err != nil {
		return nil, fmt.Errorf("malformed upstream node ID: %s: %w", upstreamNodeIDRaw, err)
	}

	logger.Info("upstream node ID is valid",
		"upstream_node_id", upstreamNodeIDRaw,
	)

	// Get upstream node's TLS public keys.
	upstreamPubKeys, err := backend.GetUpstreamTLSPubKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream node's TLS public keys: %w", err)
	}
	if len(upstreamPubKeys) == 0 {
		return nil, fmt.Errorf("upstream node has no defined TLS public keys")
	}
	logger.Info("found public keys for upstream node",
		"num_keys", len(upstreamPubKeys),
	)

	pubKeys := make(map[signature.PublicKey]bool)
	for _, pk := range upstreamPubKeys {
		pubKeys[pk] = true
	}
	creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		CommonName:    identity.CommonName,
		ServerPubKeys: pubKeys,
		GetClientCertificate: func(cri *tlsPkg.CertificateRequestInfo) (*tlsPkg.Certificate, error) {
			return ident.GetTLSCertificate(), nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS credentials: %w", err)
	}

	// Dial node
	manualResolver := manual.NewBuilderWithScheme("oasis-core-resolver")
	conn, err := cmnGrpc.Dial("oasis-core-resolver:///",
		grpc.WithTransportCredentials(creds),
		// https://github.com/grpc/grpc-go/issues/3003
		grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithResolvers(manualResolver),
	) //nolint: staticcheck
	if err != nil {
		return nil, fmt.Errorf("error dialing node: %w", err)
	}
	var resolverState resolver.State
	for _, addr := range upstreamAddrs {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return conn, nil
}

// New creates a new sentry grpc worker.
func New(backend sentry.LocalBackend, identity *identity.Identity) (*Worker, error) {
	logger := logging.GetLogger("sentry/grpc/worker")

	enabled := viper.GetBool(CfgEnabled)

	ctx, cancelCtx := context.WithCancel(context.Background())

	g := &Worker{
		enabled:   enabled,
		ctx:       ctx,
		cancelCtx: cancelCtx,
		initCh:    make(chan struct{}),
		stopCh:    make(chan struct{}),
		quitCh:    make(chan struct{}),
		logger:    logger,
		identity:  identity,
		backend:   backend,
	}

	if g.enabled {
		logger.Info("Initializing gRPC sentry worker")

		upstreamDialer := func(ctx context.Context) (*grpc.ClientConn, error) {
			upstreamConn, err := initConnection(ctx, logger, identity, backend)
			if err != nil {
				return nil, fmt.Errorf("gRPC sentry worker initializing upstream connection failure: %w", err)
			}
			return upstreamConn, nil
		}

		// Create externally-accessible proxy gRPC server.
		serverConfig := &cmnGrpc.ServerConfig{
			Name:     "sentry-grpc",
			Port:     uint16(viper.GetInt(CfgClientPort)),
			Identity: identity,
			AuthFunc: g.authFunction(),
			CustomOptions: []grpc.ServerOption{
				// All unknown requests will be proxied to the upstream grpc server.
				grpc.UnknownServiceHandler(proxy.Handler(upstreamDialer)),
			},
		}
		grpcServer, err := cmnGrpc.NewServer(serverConfig)
		if err != nil {
			return nil, err
		}
		g.grpc = grpcServer
	}

	return g, nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable Sentry gRPC worker (NOTE: This should only be enabled on gRPC Sentry nodes.)")
	Flags.String(CfgUpstreamAddress, "", "Address of the upstream node")
	Flags.String(CfgUpstreamID, "", "ID of the upstream node")
	Flags.StringSlice(CfgClientAddresses, []string{}, "Address/port(s) to use for client connections for accessing this node")
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(cmdGrpc.ClientFlags)
}
