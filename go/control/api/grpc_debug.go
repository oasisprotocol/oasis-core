package api

import (
	"context"

	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

var (
	// debugServiceName is the gRPC service name.
	debugServiceName = cmnGrpc.NewServiceName("DebugController")

	// methodSetEpoch is the SetEpoch method.
	methodSetEpoch = debugServiceName.NewMethod("SetEpoch", beacon.EpochTime(0))
	// methodWaitNodesRegistered is the WaitNodesRegistered method.
	methodWaitNodesRegistered = debugServiceName.NewMethod("WaitNodesRegistered", int(0))

	// debugServiceDesc is the gRPC service descriptor.
	debugServiceDesc = grpc.ServiceDesc{
		ServiceName: string(debugServiceName),
		HandlerType: (*DebugController)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSetEpoch.ShortName(),
				Handler:    handlerSetEpoch,
			},
			{
				MethodName: methodWaitNodesRegistered.ShortName(),
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
	var epoch beacon.EpochTime
	if err := dec(&epoch); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(DebugController).SetEpoch(ctx, epoch)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSetEpoch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(DebugController).SetEpoch(ctx, req.(beacon.EpochTime))
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
		FullMethod: methodWaitNodesRegistered.FullName(),
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

func (c *debugControllerClient) SetEpoch(ctx context.Context, epoch beacon.EpochTime) error {
	return c.conn.Invoke(ctx, methodSetEpoch.FullName(), epoch, nil)
}

func (c *debugControllerClient) WaitNodesRegistered(ctx context.Context, count int) error {
	return c.conn.Invoke(ctx, methodWaitNodesRegistered.FullName(), count, nil)
}

// NewDebugControllerClient creates a new gRPC debug controller client service.
func NewDebugControllerClient(c *grpc.ClientConn) DebugController {
	return &debugControllerClient{c}
}
