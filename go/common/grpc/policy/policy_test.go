package policy_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	cmnTesting "github.com/oasisprotocol/oasis-core/go/common/grpc/testing"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
)

var testNs = common.NewTestNamespaceFromSeed([]byte("oasis common grpc policy test ns"), 0)

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
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cmnGrpc.CBORCodec{})),
	)
	require.NoErrorf(err, "Failed to connect to the gRPC server: %v", err)
	return conn
}

func TestAccessPolicy(t *testing.T) {
	require := require.New(t)

	ctx := context.Background()
	host := "localhost"
	var port uint16 = 50123

	serverTLSCert, serverX509Cert := cmnTesting.CreateCertificate(t)
	clientTLSCert, clientX509Cert := cmnTesting.CreateCertificate(t)

	// Create a new gRPC server.
	serverConfig := &cmnGrpc.ServerConfig{
		Name:          host,
		Port:          port,
		Identity:      &identity.Identity{},
		CustomOptions: []grpc.ServerOption{grpc.CustomCodec(&cmnGrpc.CBORCodec{})}, // nolint: staticcheck
	}
	serverConfig.Identity.SetTLSCertificate(serverTLSCert)
	grpcServer, err := cmnGrpc.NewServer(serverConfig)
	require.NoErrorf(err, "Failed to create a new gRPC server: %v", err)

	serviceName := cmnGrpc.ServiceName(cmnTesting.ServiceDesc.ServiceName)

	policyChecker := policy.NewDynamicRuntimePolicyChecker(serviceName, nil)
	server := cmnTesting.NewPingServer(policy.GRPCAuthenticationFunction(policyChecker))
	policy := accessctl.NewPolicy()
	policyChecker.SetAccessPolicy(policy, testNs)

	// Register the pingServer with the PingService.
	cmnTesting.RegisterService(grpcServer.Server(), server)

	// Start gRPC server in a separate goroutine.
	err = grpcServer.Start()
	require.NoErrorf(err, "Failed to start the gRPC server: %v", err)

	clientTLSCredsWithoutCert, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		GetServerPubKeys: cmnGrpc.ServerPubKeysGetterFromCertificate(serverX509Cert),
		CommonName:       "oasis-node",
	})
	require.NoError(err, "NewClientCreds")
	clientTLSCreds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		Certificates:     []tls.Certificate{*clientTLSCert},
		GetServerPubKeys: cmnGrpc.ServerPubKeysGetterFromCertificate(serverX509Cert),
		CommonName:       "oasis-node",
	})
	require.NoError(err, "NewClientCreds")
	address := fmt.Sprintf("%s:%d", host, port)

	// Connect to the gRPC server without a client certificate.
	conn := connectToGrpcServer(ctx, t, address, clientTLSCredsWithoutCert)
	defer conn.Close()
	// Create a new ping client.
	client := cmnTesting.NewPingClient(conn)
	pingQuery := &cmnTesting.PingQuery{Namespace: testNs}
	_, err = client.Ping(ctx, pingQuery)
	require.EqualError(
		err,
		"rpc error: code = PermissionDenied desc = grpc: unexpected number of peer certificates: 0",
		"Calling Ping without a client certificate should not be allowed",
	)

	// Connect to the gRPC server with a client certificate.
	conn = connectToGrpcServer(ctx, t, address, clientTLSCreds)
	defer conn.Close()
	// Create a new ping client.
	client = cmnTesting.NewPingClient(conn)

	expectedStr := fmt.Sprintf("rpc error: code = PermissionDenied desc = grpc: calling /oasis-core.PingService/Ping method for runtime %s not allowed for client %s", testNs, accessctl.SubjectFromX509Certificate(clientX509Cert))
	_, err = client.Ping(ctx, pingQuery)
	require.EqualError(
		err,
		expectedStr,
		"Calling Ping with an empty access policy should not be allowed",
	)
	require.Equal(codes.PermissionDenied, status.Code(err), "returned gRPC error should be PermissionDenied")

	// Add a policy rule to allow the client to call Ping.
	policy = accessctl.NewPolicy()
	subject := accessctl.SubjectFromX509Certificate(clientX509Cert)
	policy.Allow(subject, accessctl.Action(cmnTesting.MethodPing.FullName()))
	policyChecker.SetAccessPolicy(policy, testNs)

	res, err := client.Ping(ctx, pingQuery)
	require.NoError(err, "Calling Ping with proper access policy set should succeed")
	require.IsType(&cmnTesting.PingResponse{}, res, "Calling Ping should return a response of the correct type")
}
