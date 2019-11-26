package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("NodeController")

	// methodRequestShutdown is the name of the RequestShutdown method.
	methodRequestShutdown = serviceName.NewMethodName("RequestShutdown")
	// methodWaitSync is the name of the WaitSync method.
	methodWaitSync = serviceName.NewMethodName("WaitSync")
	// methodIsSynced is the name of the IsSynced method.
	methodIsSynced = serviceName.NewMethodName("IsSynced")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*NodeController)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodRequestShutdown.Short(),
				Handler:    handlerRequestShutdown,
			},
			{
				MethodName: methodWaitSync.Short(),
				Handler:    handlerWaitSync,
			},
			{
				MethodName: methodIsSynced.Short(),
				Handler:    handlerIsSynced,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerRequestShutdown( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var wait bool
	if err := dec(&wait); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(NodeController).RequestShutdown(ctx, wait)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodRequestShutdown.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).RequestShutdown(ctx, req.(bool))
	}
	return interceptor(ctx, wait, info, handler)
}

func handlerWaitSync( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return nil, srv.(NodeController).WaitSync(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitSync.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).WaitSync(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerIsSynced( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(NodeController).IsSynced(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodIsSynced.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeController).IsSynced(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

// RegisterService registers a new node controller service with the given gRPC server.
func RegisterService(server *grpc.Server, service NodeController) {
	server.RegisterService(&serviceDesc, service)
}

type nodeControllerClient struct {
	conn *grpc.ClientConn
}

func (c *nodeControllerClient) RequestShutdown(ctx context.Context, wait bool) error {
	return c.conn.Invoke(ctx, methodRequestShutdown.Full(), wait, nil)
}

func (c *nodeControllerClient) WaitSync(ctx context.Context) error {
	return c.conn.Invoke(ctx, methodWaitSync.Full(), nil, nil)
}

func (c *nodeControllerClient) IsSynced(ctx context.Context) (bool, error) {
	var rsp bool
	if err := c.conn.Invoke(ctx, methodIsSynced.Full(), nil, &rsp); err != nil {
		return false, err
	}
	return rsp, nil
}

// NewNodeControllerClient creates a new gRPC node controller client service.
func NewNodeControllerClient(c *grpc.ClientConn) NodeController {
	return &nodeControllerClient{c}
}
