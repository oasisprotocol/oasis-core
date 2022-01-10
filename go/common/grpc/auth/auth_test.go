package auth_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	commonTesting "github.com/oasisprotocol/oasis-core/go/common/grpc/testing"
)

const (
	recvTimeout  = 5 * time.Second
	numWaitPings = 3
)

// rejectAll is an auth function that rejects all requests.
func rejectAll(ctx context.Context, fullMethodName string, req interface{}) error {
	return status.Errorf(codes.PermissionDenied, "rejecting all")
}

type testCase struct {
	serverConfig  *commonGrpc.ServerConfig
	expectedError error
}

func TestGRPCAuth(t *testing.T) {
	host := "localhost"
	var port uint16 = 52123

	testCases := []*testCase{
		// Default NoAuth.
		{
			serverConfig: &commonGrpc.ServerConfig{
				Name: host,
				Port: port,
			},
			expectedError: nil,
		},
		// Explicit NoAuth.
		{
			serverConfig: &commonGrpc.ServerConfig{
				Name:     host,
				Port:     port,
				AuthFunc: auth.NoAuth,
			},
			expectedError: nil,
		},
		// Reject all.
		{
			serverConfig: &commonGrpc.ServerConfig{
				Name:     host,
				Port:     port,
				AuthFunc: rejectAll,
			},
			expectedError: status.Errorf(codes.PermissionDenied, "rejecting all"),
		},
	}

	for _, testCase := range testCases {
		testAuth(t, testCase)
	}
}

func testAuth(t *testing.T, testCase *testCase) {
	require := require.New(t)
	ctx := context.Background()

	grpcServer, err := commonGrpc.NewServer(testCase.serverConfig)
	require.NoErrorf(err, "Failed to create a new gRPC server: %v", err)

	server := commonTesting.NewPingServer(testCase.serverConfig.AuthFunc)
	// Register the pingServer with the PingService.
	commonTesting.RegisterService(grpcServer.Server(), server)

	// Start gRPC server in a separate goroutine.
	err = grpcServer.Start()
	require.NoErrorf(err, "Failed to start the gRPC server: %v", err)
	defer func() {
		grpcServer.Stop()
		grpcServer.Cleanup()
	}()

	// Connect to gRPC server.
	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("%s:%d", testCase.serverConfig.Name, testCase.serverConfig.Port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&commonGrpc.CBORCodec{})),
	)

	require.NoErrorf(err, "Failed to connect to the gRPC server: %v", err)
	defer conn.Close()

	// Create a new ping client.
	client := commonTesting.NewPingClient(conn)
	pingQuery := &commonTesting.PingQuery{}
	// Test Ping.
	res, err := client.Ping(ctx, pingQuery)
	switch testCase.expectedError {
	case nil:
		require.NoError(err, "Calling Ping should succeed")
		require.IsType(&commonTesting.PingResponse{}, res, "Calling Ping should return a response of the correct type")
	default:
		require.EqualError(err, testCase.expectedError.Error(), "Calling Ping should fail")
	}

	// Test WatchPings.
	ch, sub, err := client.WatchPings(ctx, pingQuery)
	require.NoError(err, "Calling WatchPings shouldn't fail")
	defer sub.Close()

	switch testCase.expectedError {
	case nil:
		for i := 0; i < numWaitPings; i++ {
			select {
			case res, ok := <-ch:
				require.True(ok, "should receive ping")
				require.IsType(&commonTesting.PingResponse{}, res, "Calling WatchPings should return a response of the correct type")
				break
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive WatchPings")
			}
		}
	default:
		select {
		case res, ok := <-ch:
			// XXX: In streaming cases error is currently not propagated.
			require.False(ok, "Calling WatchPing should fail")
			require.Nil(res, "Failing WatchPing result is nil")
			break
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive WatchPings")
		}

	}
}
