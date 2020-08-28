package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	cmnTesting "github.com/oasisprotocol/oasis-core/go/common/grpc/testing"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
)

const (
	recvTimeout  = 5 * time.Second
	numWaitPings = 3
)

func connectToGrpcServer(
	ctx context.Context,
	t *testing.T,
	address string,
	creds credentials.TransportCredentials,
) *grpc.ClientConn {
	require := require.New(t)
	conn, err := grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&commonGrpc.CBORCodec{})),
	)
	require.NoErrorf(err, "Failed to connect to the gRPC server: %v", err)
	return conn
}

func TestGRPCProxy(t *testing.T) {
	require := require.New(t)

	ctx := context.Background()
	host := "localhost"
	var port uint16 = 51123

	serverTLSCert, serverX509Cert := cmnTesting.CreateCertificate(t)
	clientTLSCert, _ := cmnTesting.CreateCertificate(t)

	// Create a new gRPC server.
	serverConfig := &commonGrpc.ServerConfig{
		Name:          host,
		Port:          port,
		Identity:      &identity.Identity{},
		CustomOptions: []grpc.ServerOption{grpc.CustomCodec(&commonGrpc.CBORCodec{})}, // nolint: staticcheck
	}
	serverConfig.Identity.SetTLSCertificate(serverTLSCert)
	grpcServer, err := commonGrpc.NewServer(serverConfig)
	require.NoErrorf(err, "Failed to create a new gRPC server: %v", err)

	// Register the pingServer with the PingService.
	server := cmnTesting.NewPingServer(auth.NoAuth)
	cmnTesting.RegisterService(grpcServer.Server(), server)

	// Start gRPC server in a separate goroutine.
	err = grpcServer.Start()
	require.NoErrorf(err, "Failed to start the gRPC server: %v", err)

	clientTLSCreds, err := commonGrpc.NewClientCreds(&commonGrpc.ClientOptions{
		Certificates:     []tls.Certificate{*clientTLSCert},
		GetServerPubKeys: commonGrpc.ServerPubKeysGetterFromCertificate(serverX509Cert),
		CommonName:       "oasis-node",
	})
	require.NoError(err, "NewClientCreds")

	// Create upstream dialer.
	upstreamDialer := func(ctx context.Context) (*grpc.ClientConn, error) {
		// Connect to gRPC server.
		address := fmt.Sprintf("%s:%d", host, port)
		conn := connectToGrpcServer(ctx, t, address, clientTLSCreds)
		return conn, nil
	}

	// Create a proxy gRPC server.
	proxyServerConfig := &commonGrpc.ServerConfig{
		Name:     host,
		Port:     port + 1,
		Identity: &identity.Identity{},
		CustomOptions: []grpc.ServerOption{
			// All unknown requests will be proxied to the grpc server above.
			grpc.UnknownServiceHandler(Handler(upstreamDialer)),
		},
	}
	proxyServerConfig.Identity.SetTLSCertificate(serverTLSCert)
	proxyGrpcServer, err := commonGrpc.NewServer(proxyServerConfig)
	require.NoErrorf(err, "Failed to create a proxy gRPC server: %v", err)

	err = proxyGrpcServer.Start()
	require.NoErrorf(err, "Failed to start the proxy gRPC server: %v", err)

	// Connect to the proxy grpc server.
	address := fmt.Sprintf("%s:%d", host, port+1)
	proxyConn := connectToGrpcServer(ctx, t, address, clientTLSCreds)
	defer proxyConn.Close()

	// Create a new ping client.
	upstreamAddress := fmt.Sprintf("%s:%d", host, port)
	upstreamConn := connectToGrpcServer(ctx, t, upstreamAddress, clientTLSCreds)
	defer upstreamConn.Close()
	client := cmnTesting.NewPingClient(upstreamConn)
	pingQuery := &cmnTesting.PingQuery{}
	// Test Ping.
	res, err := client.Ping(ctx, pingQuery)
	require.NoError(err, "Calling Ping with proper access policy set should succeed")
	require.IsType(&cmnTesting.PingResponse{}, res, "Calling Ping should return a response of the correct type")

	// Create a ping client to the proxy server.
	proxyClient := cmnTesting.NewPingClient(proxyConn)
	res, err = proxyClient.Ping(ctx, pingQuery)
	require.NoError(err, "Calling Ping on proxy server with proper access policy set should succeed")
	require.IsType(&cmnTesting.PingResponse{}, res, "Calling Ping should return a response of the correct type")

	// Test missing method.
	res, err = client.MissingMethod(ctx, pingQuery)
	require.Nil(res, "Missing method result should be nil")
	require.Error(err, "Non existing method should fail")
	require.Equal(codes.Unimplemented, status.Code(err), "Unimplemented error")

	// Proxy server should propagate errors.
	res, err = proxyClient.MissingMethod(ctx, pingQuery)
	require.Nil(res, "Missing method result should be nil")
	require.Error(err, "Non existing method should fail")
	require.Equal(codes.Unimplemented, status.Code(err), "Unimplemented error")

	// Test streaming WatchPings.
	ch, sub, err := client.WatchPings(ctx, pingQuery)
	require.NoError(err, "Calling WatchPings shouldn't fail")
	defer sub.Close()
	for i := 0; i < numWaitPings; i++ {
		select {
		case res, ok := <-ch:
			require.True(ok, "should receive ping")
			require.IsType(&cmnTesting.PingResponse{}, res, "Calling WatchPings should return a response of the correct type")
			break
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive WatchPings")
		}
	}

	// Test proxied streaming WatchPings.
	chP, subP, errP := proxyClient.WatchPings(ctx, pingQuery)
	require.NoError(errP, "Calling WatchPings shouldn't fail")
	defer subP.Close()
	for i := 0; i < numWaitPings; i++ {
		select {
		case res, ok := <-chP:
			require.True(ok, "should receive ping")
			require.IsType(&cmnTesting.PingResponse{}, res, "Calling WatchPings should return a response of the correct type")
			break
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive WatchPings")
		}
	}
}
