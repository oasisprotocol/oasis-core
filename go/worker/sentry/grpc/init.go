// Package grpc implements a gRPC sentry worker.
package grpc

import (
	"context"
	tlsPkg "crypto/tls"
	"crypto/x509"
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	"github.com/oasislabs/oasis-core/go/common/grpc/proxy"
	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/worker/common/configparser"
)

const (
	// CfgEnabled enables the sentry grpc worker.
	CfgEnabled = "worker.sentry.grpc.enabled"

	// CfgUpstreamAddress is the grpc address of the upstream node.
	CfgUpstreamAddress = "worker.sentry.grpc.upstream.address"

	// CfgUpstreamCert is the path to the certificate files of the upstream node.
	CfgUpstreamCert = "worker.sentry.grpc.upstream.cert"

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

func initConnection(ident *identity.Identity) (*upstreamConn, error) {
	var err error

	addr := viper.GetString(CfgUpstreamAddress)
	certFile := viper.GetString(CfgUpstreamCert)

	upstreamAddrs, err := configparser.ParseAddressList([]string{addr})
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %s: %w", addr, err)
	}
	upstreamCerts, err := configparser.ParseCertificateFiles([]string{certFile})
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate file %s: %w", certFile, err)
	}

	certPool := x509.NewCertPool()
	for _, cert := range upstreamCerts {
		certPool.AddCert(cert)
	}
	creds := credentials.NewTLS(&tlsPkg.Config{
		Certificates: []tlsPkg.Certificate{*ident.TLSCertificate},
		RootCAs:      certPool,
		ServerName:   identity.CommonName,
	})

	// Dial node
	manualResolver, address, cleanupCb := manual.NewManualResolver()
	conn, err := cmnGrpc.Dial(address,
		grpc.WithTransportCredentials(creds),
		// https://github.com/grpc/grpc-go/issues/3003
		grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	) //nolint: staticcheck
	if err != nil {
		cleanupCb()
		return nil, fmt.Errorf("error dialing node: %w", err)
	}
	var resolverState resolver.State
	for _, addr := range upstreamAddrs {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return &upstreamConn{
		conn:              conn,
		resolverCleanupCb: cleanupCb,
	}, nil
}

// New creates a new sentry grpc worker.
func New(identity *identity.Identity) (*Worker, error) {
	logger := logging.GetLogger("sentry/grpc/worker")

	enabled := viper.GetBool(CfgEnabled)

	ctx, cancelCtx := context.WithCancel(context.Background())

	g := &Worker{
		enabled:            enabled,
		ctx:                ctx,
		cancelCtx:          cancelCtx,
		initCh:             make(chan struct{}),
		stopCh:             make(chan struct{}),
		quitCh:             make(chan struct{}),
		logger:             logger,
		identity:           identity,
		grpcPolicyCheckers: make(map[cmnGrpc.ServiceName]*policy.DynamicRuntimePolicyChecker),
	}

	if g.enabled {
		logger.Info("Initializing gRPC sentry worker")

		upstreamConn, err := initConnection(identity)
		if err != nil {
			return nil, fmt.Errorf("gRPC sentry worker initializing upstream connection failure: %w", err)
		}
		g.upstreamConn = upstreamConn

		// Create externally-accessible proxy gRPC server.
		serverConfig := &cmnGrpc.ServerConfig{
			Name:        "sentry-grpc",
			Port:        uint16(viper.GetInt(CfgClientPort)),
			Certificate: identity.TLSCertificate,
			AuthFunc:    g.authFunction(),
			CustomOptions: []grpc.ServerOption{
				// All unknown requests will be proxied to the upstream grpc server.
				grpc.UnknownServiceHandler(proxy.Handler(upstreamConn.conn)),
			},
		}
		grpc, err := cmnGrpc.NewServer(serverConfig)
		if err != nil {
			return nil, err
		}
		g.grpc = grpc
	}

	return g, nil
}

func init() {
	Flags.Bool(CfgEnabled, false, "Enable Sentry gRPC worker (NOTE: This should only be enabled on gRPC Sentry nodes.)")
	Flags.String(CfgUpstreamAddress, "", "Address of the upstream node")
	Flags.String(CfgUpstreamCert, "", "Path to tls certificate of the upstream node")
	Flags.StringSlice(CfgClientAddresses, []string{}, "Address/port(s) to use for client connections for accessing this node")
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")

	_ = viper.BindPFlags(Flags)
}
