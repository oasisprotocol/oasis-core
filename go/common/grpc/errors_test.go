package grpc

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/errors"
)

var errTest = errors.New("test/grpc/errors", 1, "just testing errors")

type ErrorTestRequest struct {
}

type ErrorTestResponse struct {
}

type ErrorTestService interface {
	ErrorTest(context.Context, *ErrorTestRequest) (*ErrorTestResponse, error)
}

type errorTestServer struct {
}

func (s *errorTestServer) ErrorTest(ctx context.Context, req *ErrorTestRequest) (*ErrorTestResponse, error) {
	return &ErrorTestResponse{}, errTest
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

var errorTestServiceDesc = grpc.ServiceDesc{
	ServiceName: "ErrorTestService",
	HandlerType: (*ErrorTestService)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ErrorTest",
			Handler:    handlerErrorTest,
		},
	},
	Streams: []grpc.StreamDesc{},
}

func handlerErrorTest( // nolint: golint
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

	conn, err := Dial("unix:"+f.Name(), grpc.WithInsecure())
	require.NoError(err, "Dial")
	defer conn.Close()
	client := &errorTestClient{conn}

	_, err = client.ErrorTest(context.Background(), &ErrorTestRequest{})
	require.Error(err, "ErrorTest should return an error")
	require.Equal(err, errTest, "errors should be properly mapped")
}
