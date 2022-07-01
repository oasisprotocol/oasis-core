package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const numMultiPings uint32 = 10

var (
	_ MultiPingServer = (*multiPingServer)(nil)
	_ MultiPingClient = (*multiPingClient)(nil)
)

// Request types

type MultiPingUnaryRequest struct{}

type MultiPingUnaryResponse struct{}

type MultiPingStreamRequest struct{}

type MultiPingStreamResponse struct{}

func sendMultiPings(stream grpc.ServerStream) uint32 {
	for i := uint32(0); i < numMultiPings; i++ {
		_ = stream.SendMsg(&MultiPingStreamResponse{})
	}
	return numMultiPings
}

// Server-side

type MultiPingServer interface {
	Ping(context.Context) (*MultiPingUnaryResponse, error)
	MultiPing(grpc.ServerStream) error
}

type multiPingServer struct {
	pingCount      uint32
	multiPingCount uint32
}

func (s *multiPingServer) Ping(ctx context.Context) (*MultiPingUnaryResponse, error) {
	atomic.AddUint32(&s.pingCount, 1)
	return &MultiPingUnaryResponse{}, nil
}

func (s *multiPingServer) MultiPing(stream grpc.ServerStream) error {
	atomic.AddUint32(&s.multiPingCount, sendMultiPings(stream))
	return nil
}

func (s *multiPingServer) GetPingCount() uint32 {
	return atomic.LoadUint32(&s.pingCount)
}

func (s *multiPingServer) GetMultiPingCount() uint32 {
	return atomic.LoadUint32(&s.multiPingCount)
}

// Client-side

type MultiPingClient interface {
	Ping(ctx context.Context, opts ...grpc.CallOption) (uint32, error)
	MultiPing(ctx context.Context, opts ...grpc.CallOption) (uint32, error)
}

type multiPingClient struct {
	cc *grpc.ClientConn

	pingCount      uint32
	multiPingCount uint32
}

func (c *multiPingClient) Ping(ctx context.Context, opts ...grpc.CallOption) (uint32, error) {
	in := &MultiPingUnaryRequest{}
	out := new(MultiPingUnaryResponse)
	err := c.cc.Invoke(ctx, "/MultiPingService/Ping", in, out, opts...)
	if err != nil {
		return 0, err
	}
	atomic.AddUint32(&c.pingCount, 1)
	return 1, nil
}

func (c *multiPingClient) MultiPing(ctx context.Context, opts ...grpc.CallOption) (uint32, error) {
	in := &MultiPingStreamRequest{}
	stream, err := c.cc.NewStream(ctx, &multiServiceDesc.Streams[0], "/MultiPingService/MultiPing", opts...)
	if err != nil {
		return 0, err
	}
	if err := stream.SendMsg(in); err != nil {
		return 0, err
	}
	if err := stream.CloseSend(); err != nil {
		return 0, err
	}

	var count uint32
	m := MultiPingStreamResponse{}
	for {
		err := stream.RecvMsg(&m)
		if err == io.EOF {
			atomic.AddUint32(&c.multiPingCount, count)
			return count, nil
		}
		if err != nil {
			return 0, nil
		}
		count++
	}
}

func (c *multiPingClient) GetPingCount() uint32 {
	return atomic.LoadUint32(&c.pingCount)
}

func (c *multiPingClient) GetMultiPingCount() uint32 {
	return atomic.LoadUint32(&c.multiPingCount)
}

// Grpc glue

var multiServiceDesc = grpc.ServiceDesc{
	ServiceName: "MultiPingService",
	HandlerType: (*MultiPingServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    multiPingUnaryHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "MultiPing",
			Handler:       multiPingStreamHandler,
			ServerStreams: true,
		},
	},
}

func multiPingUnaryHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	pq := new(MultiPingUnaryRequest)
	if err := dec(pq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MultiPingServer).Ping(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/MultiPingService/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MultiPingServer).Ping(ctx)
	}
	return interceptor(ctx, pq, info, handler)
}

func multiPingStreamHandler(
	srv interface{},
	stream grpc.ServerStream,
) error {
	m := new(MultiPingStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(MultiPingServer).MultiPing(stream)
}

// Actual test

func callClient(
	ctx context.Context,
	expected uint32,
	call func(context.Context, ...grpc.CallOption) (uint32, error),
	opts ...grpc.CallOption,
) <-chan error {
	syncCh := make(chan error)
	go func() {
		defer close(syncCh)
		cnt, err := call(ctx, opts...)
		if err == nil && cnt != expected {
			err = errors.New("Ping didn't receive proper count of pings")
		}
		syncCh <- err
	}()
	return syncCh
}

func TestGrpcWrapper(t *testing.T) {
	require := require.New(t)

	ctx := context.Background()
	host := "localhost"
	var port uint16 = 50124

	// Create a new gRPC server.
	serverConfig := &ServerConfig{
		Name:           host,
		Port:           port,
		CustomOptions:  []grpc.ServerOption{grpc.CustomCodec(&CBORCodec{})}, // nolint: staticcheck
		InstallWrapper: true,
	}
	grpcServer, err := NewServer(serverConfig)
	require.NoErrorf(err, "Failed to create a new gRPC server: %v", err)

	// Create and register a new multiPingServer.
	server := &multiPingServer{}
	grpcServer.Server().RegisterService(&multiServiceDesc, server)

	// Start gRPC server in a separate goroutine.
	err = grpcServer.Start()
	defer grpcServer.Stop()
	require.NoErrorf(err, "Failed to start the gRPC server: %v", err)

	// Connect to the gRPC server without a client certificate.
	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("%s:%d", host, port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&CBORCodec{})),
	)
	require.NoErrorf(err, "Failed to connect to gRPC server: %v", err)
	defer conn.Close()

	// Create a new ping client.
	client := &multiPingClient{
		cc: conn,
	}

	var count uint32
	var serverPingCount uint32
	var serverMultiPingCount uint32
	var syncCh <-chan error
	var req *WrappedRequest

	// No active interceptor.
	count, err = client.Ping(ctx)
	require.NoError(err, "Ping")
	require.Equal(uint32(1), count, "Ping Client Count")
	require.Equal(uint32(1), server.GetPingCount(), "Ping Server Count")

	count, err = client.MultiPing(ctx)
	require.NoError(err, "MultiPing")
	require.Equal(numMultiPings, count, "MultiPing")
	require.Equal(numMultiPings, server.GetMultiPingCount(), "MultiPing Server Count")
	serverMultiPingCount = server.GetMultiPingCount()
	serverPingCount = server.GetPingCount()

	// With interceptor.
	serverCh := grpcServer.RegisterServiceWrapper("/MultiPingService/", func(*grpc.Server) {
		// Server already registered above, nothing to do here.
	})

	syncCh = callClient(ctx, 1, client.Ping)
	req = <-serverCh
	require.NotNil(req.Unary, "Wrapped server ping pull didn't get unary")
	require.Nil(req.Stream, "Wrapped server ping pull got stream")
	req.Respond(&MultiPingUnaryResponse{}, nil)
	err = <-syncCh
	require.NoError(err, "Wrapped client ping got error")
	require.Equal(serverPingCount, server.GetPingCount(), "Server count should be unchanged")

	syncCh = callClient(ctx, numMultiPings, client.MultiPing)
	req = <-serverCh
	require.Nil(req.Unary, "Wrapped server multi-ping pull got unary")
	require.NotNil(req.Stream, "Wrapped server multi-ping pull didn't get stream")
	sendMultiPings(req.Stream.Stream)
	req.Respond(nil, nil)
	err = <-syncCh
	require.NoError(err, "Wrapped client ping got error")
	require.Equal(serverMultiPingCount, server.GetMultiPingCount(), "Server count should be unchanged")

	// Test transparent forwarding.
	var resp interface{}
	syncCh = callClient(ctx, 1, client.Ping)
	req = <-serverCh
	require.NotNil(req.Unary, "Forwarding server ping pull didn't get unary")
	require.Nil(req.Stream, "Forwarding server ping pull got stream")
	resp, err = req.Forward()
	req.Respond(resp, err)
	err = <-syncCh
	require.NoError(err, "Forwarding client ping got error")
	require.Equal(serverPingCount+1, server.GetPingCount(), "Server count should change")

	syncCh = callClient(ctx, numMultiPings, client.MultiPing)
	req = <-serverCh
	require.Nil(req.Unary, "Forwarding server multi-ping pull got unary")
	require.NotNil(req.Stream, "Forwarding server multi-ping pull didn't get stream")
	resp, err = req.Forward()
	req.Respond(resp, err)
	err = <-syncCh
	require.NoError(err, "Forwarding client ping got error")
	require.Equal(serverMultiPingCount+numMultiPings, server.GetMultiPingCount(), "Server count should change")
}
