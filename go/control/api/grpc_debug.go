package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

var (
	// debugServiceName is the gRPC service name.
	debugServiceName = cmnGrpc.NewServiceName("DebugController")

	// methodSetEpoch is the name of the SetEpoch method.
	methodSetEpoch = debugServiceName.NewMethodName("SetEpoch")
	// methodWaitNodesRegistered is the name of the WaitNodesRegistered method.
	methodWaitNodesRegistered = debugServiceName.NewMethodName("WaitNodesRegistered")

	// debugServiceDesc is the gRPC service descriptor.
	debugServiceDesc = grpc.ServiceDesc{
		ServiceName: string(debugServiceName),
		HandlerType: (*DebugController)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSetEpoch.Short(),
				Handler:    handlerSetEpoch,
			},
			{
				MethodName: methodWaitNodesRegistered.Short(),
				Handler:    handlerWaitNodesRegistered,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerSetEpoch( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var epoch epochtime.EpochTime
	if err := dec(&epoch); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(DebugController).SetEpoch(ctx, epoch)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSetEpoch.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(DebugController).SetEpoch(ctx, req.(epochtime.EpochTime))
	}
	return interceptor(ctx, epoch, info, handler)
}

func handlerWaitNodesRegistered( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var count int
	if err := dec(&count); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(DebugController).WaitNodesRegistered(ctx, count)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitNodesRegistered.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(DebugController).WaitNodesRegistered(ctx, req.(int))
	}
	return interceptor(ctx, count, info, handler)
}

// RegisterDebugService registers a new debug controller service with the given gRPC server.
func RegisterDebugService(server *grpc.Server, service DebugController) {
	server.RegisterService(&debugServiceDesc, service)
}

type debugControllerClient struct {
	conn *grpc.ClientConn
}

func (c *debugControllerClient) SetEpoch(ctx context.Context, epoch epochtime.EpochTime) error {
	return c.conn.Invoke(ctx, methodSetEpoch.Full(), epoch, nil)
}

func (c *debugControllerClient) WaitNodesRegistered(ctx context.Context, count int) error {
	return c.conn.Invoke(ctx, methodWaitNodesRegistered.Full(), count, nil)
}

// NewDebugControllerClient creates a new gRPC debug controller client service.
func NewDebugControllerClient(c *grpc.ClientConn) DebugController {
	return &debugControllerClient{c}
}
