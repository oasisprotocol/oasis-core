package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Sentry")

	// methodGetAddresses is the GetAddresses method.
	methodGetAddresses = serviceName.NewMethod("GetAddresses", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetAddresses.ShortName(),
				Handler:    handlerGetAddresses,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerGetAddresses(
	srv interface{},
	ctx context.Context,
	_ func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).GetAddresses(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetAddresses.FullName(),
	}
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		return srv.(Backend).GetAddresses(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

// RegisterService registers a new sentry service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

// Client is a gRPC sentry client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC sentry client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{
		conn: c,
	}
}

func (c *Client) GetAddresses(ctx context.Context) (*SentryAddresses, error) {
	var rsp SentryAddresses
	if err := c.conn.Invoke(ctx, methodGetAddresses.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}
