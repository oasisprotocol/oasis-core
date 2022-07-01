package grpc

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
)

var errTest = errors.New("test/grpc/errors", 1, "just testing errors")

type ErrorTestRequest struct{}

type ErrorTestResponse struct{}

type ErrorTestService interface {
	ErrorTest(context.Context, *ErrorTestRequest) (*ErrorTestResponse, error)
	ErrorTestWithContext(context.Context, *ErrorTestRequest) (*ErrorTestResponse, error)
	ErrorStatusTest(context.Context, *ErrorTestRequest) (*ErrorTestResponse, error)
}

type errorTestServer struct{}

func (s *errorTestServer) ErrorTest(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	return &ErrorTestResponse{}, errTest
}

func (s *errorTestServer) ErrorTestWithContext(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	return &ErrorTestResponse{}, errors.WithContext(errTest, "my test context")
}

func (s *errorTestServer) ErrorStatusTest(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	return nil, io.ErrUnexpectedEOF
}

type errorTestClient struct {
	cc *grpc.ClientConn
}

func (c *errorTestClient) ErrorTest(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	rsp := new(ErrorTestResponse)
	err := c.cc.Invoke(ctx, "/ErrorTestService/ErrorTest", req, rsp)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *errorTestClient) ErrorTestWithContext(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	rsp := new(ErrorTestResponse)
	err := c.cc.Invoke(ctx, "/ErrorTestService/ErrorTestWithContext", req, rsp)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *errorTestClient) ErrorStatusTest(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	rsp := new(ErrorTestResponse)
	err := c.cc.Invoke(ctx, "/ErrorTestService/ErrorStatusTest", req, rsp)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

var errorTestServiceDesc = grpc.ServiceDesc{
	ServiceName: "ErrorTestService",
	HandlerType: (*ErrorTestService)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ErrorTest",
			Handler:    handlerErrorTest,
		},
		{
			MethodName: "ErrorTestWithContext",
			Handler:    handlerErrorTestWithContext,
		},
		{
			MethodName: "ErrorStatusTest",
			Handler:    handlerErrorStatusTest,
		},
	},
	Streams: []grpc.StreamDesc{},
}

func handlerErrorTest(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	req := new(ErrorTestRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ErrorTestService).ErrorTest(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ErrorTestService/ErrorTest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ErrorTestService).ErrorTest(ctx, req.(*ErrorTestRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func handlerErrorTestWithContext(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	req := new(ErrorTestRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ErrorTestService).ErrorTest(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ErrorTestService/ErrorTestWithContext",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ErrorTestService).ErrorTestWithContext(ctx, req.(*ErrorTestRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func handlerErrorStatusTest(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	req := new(ErrorTestRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ErrorTestService).ErrorStatusTest(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ErrorTestService/ErrorStatusTest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ErrorTestService).ErrorStatusTest(ctx, req.(*ErrorTestRequest))
	}
	return interceptor(ctx, req, info, handler)
}

func TestErrorMapping(t *testing.T) {
	require := require.New(t)

	// Generate temporary filename for the socket.
	f, err := ioutil.TempFile("", "oasis-grpc-error-test-socket")
	require.NoError(err, "TempFile")
	// Remove the file as we only need the name.
	f.Close()
	os.Remove(f.Name())

	cfg := &ServerConfig{
		Path: f.Name(),
	}
	grpcServer, err := NewServer(cfg)
	require.NoError(err, "NewServer")
	defer os.Remove(f.Name())

	grpcServer.Server().RegisterService(&errorTestServiceDesc, &errorTestServer{})

	err = grpcServer.Start()
	require.NoErrorf(err, "Failed to start the gRPC server")

	conn, err := Dial("unix:"+f.Name(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(err, "Dial")
	defer conn.Close()
	client := &errorTestClient{conn}

	_, err = client.ErrorTest(context.Background(), &ErrorTestRequest{})
	require.Error(err, "ErrorTest should return an error")
	require.Equal(errTest, err, "errors should be properly mapped")

	_, err = client.ErrorTestWithContext(context.Background(), &ErrorTestRequest{})
	require.Error(err, "ErrorTestWithContext should return an error")
	require.True(errors.Is(err, errTest), "errors should be properly mapped")
	require.Equal("just testing errors: my test context", err.Error())
	require.Equal("my test context", errors.Context(err))

	_, err = client.ErrorStatusTest(context.Background(), &ErrorTestRequest{})
	require.Error(err, "ErrorStatusTest should return an error")
	require.True(IsErrorCode(err, codes.Unknown), "ErrorStatusTest should have code unknown")
	st := GetErrorStatus(err)
	require.NotNil(st, "GetErrorStatus should not be nil")
	s, _ := status.FromError(io.ErrUnexpectedEOF)
	require.Equal(s.Err().Error(), st.Err().Error(), "GetErrorStatus.Status should be io.ErrUnexpectedEOF")
}
