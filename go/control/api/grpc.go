package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	upgradeApi "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("NodeController")

	// methodRequestShutdown is the RequestShutdown method.
	methodRequestShutdown = serviceName.NewMethod("RequestShutdown", false)
	// methodWaitSync is the WaitSync method.
	methodWaitSync = serviceName.NewMethod("WaitSync", nil)
	// methodIsSynced is the IsSynced method.
	methodIsSynced = serviceName.NewMethod("IsSynced", nil)
	// methodWaitReady is the WaitReady method.
	methodWaitReady = serviceName.NewMethod("WaitReady", nil)
	// methodIsReady is the IsReady method.
	methodIsReady = serviceName.NewMethod("IsReady", nil)
	// methodUpgradeBinary is the UpgradeBinary method.
	methodUpgradeBinary = serviceName.NewMethod("UpgradeBinary", upgradeApi.Descriptor{})
	// methodCancelUpgrade is the CancelUpgrade method.
	methodCancelUpgrade = serviceName.NewMethod("CancelUpgrade", nil)
	// methodGetStatus is the GetStatus method.
	methodGetStatus = serviceName.NewMethod("GetStatus", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*NodeController)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodRequestShutdown.ShortName(),
				Handler:    handlerRequestShutdown,
			},
			{
				MethodName: methodWaitSync.ShortName(),
				Handler:    handlerWaitSync,
			},
			{
				MethodName: methodIsSynced.ShortName(),
				Handler:    handlerIsSynced,
			},
			{
				MethodName: methodWaitReady.ShortName(),
				Handler:    handlerWaitReady,
			},
			{
				MethodName: methodIsReady.ShortName(),
				Handler:    handlerIsReady,
			},
			{
				MethodName: methodUpgradeBinary.ShortName(),
				Handler:    handlerUpgradeBinary,
			},
			{
				MethodName: methodCancelUpgrade.ShortName(),
				Handler:    handlerCancelUpgrade,
			},
			{
				MethodName: methodGetStatus.ShortName(),
				Handler:    handlerGetStatus,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerRequestShutdown(
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
		FullMethod: methodRequestShutdown.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).RequestShutdown(ctx, req.(bool))
	}
	return interceptor(ctx, wait, info, handler)
}

func handlerWaitSync(
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
		FullMethod: methodWaitSync.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).WaitSync(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerIsSynced(
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
		FullMethod: methodIsSynced.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeController).IsSynced(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerWaitReady(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return nil, srv.(NodeController).WaitReady(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitReady.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).WaitReady(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerIsReady(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(NodeController).IsReady(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodIsSynced.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeController).IsReady(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerUpgradeBinary(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var descriptor upgradeApi.Descriptor
	if err := dec(&descriptor); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(NodeController).UpgradeBinary(ctx, &descriptor)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodUpgradeBinary.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).UpgradeBinary(ctx, req.(*upgradeApi.Descriptor))
	}
	return interceptor(ctx, &descriptor, info, handler)
}

func handlerCancelUpgrade(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var descriptor upgradeApi.Descriptor
	if err := dec(&descriptor); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(NodeController).CancelUpgrade(ctx, &descriptor)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodCancelUpgrade.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(NodeController).CancelUpgrade(ctx, req.(*upgradeApi.Descriptor))
	}
	return interceptor(ctx, &descriptor, info, handler)
}

func handlerGetStatus(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(NodeController).GetStatus(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatus.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeController).GetStatus(ctx)
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
	return c.conn.Invoke(ctx, methodRequestShutdown.FullName(), wait, nil)
}

func (c *nodeControllerClient) WaitSync(ctx context.Context) error {
	return c.conn.Invoke(ctx, methodWaitSync.FullName(), nil, nil)
}

func (c *nodeControllerClient) IsSynced(ctx context.Context) (bool, error) {
	var rsp bool
	if err := c.conn.Invoke(ctx, methodIsSynced.FullName(), nil, &rsp); err != nil {
		return false, err
	}
	return rsp, nil
}

func (c *nodeControllerClient) WaitReady(ctx context.Context) error {
	return c.conn.Invoke(ctx, methodWaitReady.FullName(), nil, nil)
}

func (c *nodeControllerClient) IsReady(ctx context.Context) (bool, error) {
	var rsp bool
	if err := c.conn.Invoke(ctx, methodIsReady.FullName(), nil, &rsp); err != nil {
		return false, err
	}
	return rsp, nil
}

func (c *nodeControllerClient) UpgradeBinary(ctx context.Context, descriptor *upgradeApi.Descriptor) error {
	return c.conn.Invoke(ctx, methodUpgradeBinary.FullName(), descriptor, nil)
}

func (c *nodeControllerClient) CancelUpgrade(ctx context.Context, descriptor *upgradeApi.Descriptor) error {
	return c.conn.Invoke(ctx, methodCancelUpgrade.FullName(), descriptor, nil)
}

func (c *nodeControllerClient) GetStatus(ctx context.Context) (*Status, error) {
	var rsp Status
	if err := c.conn.Invoke(ctx, methodGetStatus.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// NewNodeControllerClient creates a new gRPC node controller client service.
func NewNodeControllerClient(c *grpc.ClientConn) NodeController {
	return &nodeControllerClient{c}
}
