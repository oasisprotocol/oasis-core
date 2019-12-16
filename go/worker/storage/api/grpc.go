package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("StorageWorker")

	// methodGetLastSyncedRound is the name of the GetLastSyncedRound method.
	methodGetLastSyncedRound = serviceName.NewMethodName("GetLastSyncedRound")
	// methodForceFinalize is the name of the ForceFinalize method.
	methodForceFinalize = serviceName.NewMethodName("ForceFinalize")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*StorageWorker)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetLastSyncedRound.Short(),
				Handler:    handlerGetLastSyncedRound,
			},
			{
				MethodName: methodForceFinalize.Short(),
				Handler:    handlerForceFinalize,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerGetLastSyncedRound( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(GetLastSyncedRoundRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageWorker).GetLastSyncedRound(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLastSyncedRound.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageWorker).GetLastSyncedRound(ctx, req.(*GetLastSyncedRoundRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerForceFinalize( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(ForceFinalizeRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(StorageWorker).ForceFinalize(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodForceFinalize.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(StorageWorker).ForceFinalize(ctx, req.(*ForceFinalizeRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

// RegisterService registers a new storage worker service with the given gRPC server.
func RegisterService(server *grpc.Server, service StorageWorker) {
	server.RegisterService(&serviceDesc, service)
}

type storageWorkerClient struct {
	conn *grpc.ClientConn
}

func (c *storageWorkerClient) GetLastSyncedRound(ctx context.Context, req *GetLastSyncedRoundRequest) (*GetLastSyncedRoundResponse, error) {
	var rsp GetLastSyncedRoundResponse
	if err := c.conn.Invoke(ctx, methodGetLastSyncedRound.Full(), req, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *storageWorkerClient) ForceFinalize(ctx context.Context, req *ForceFinalizeRequest) error {
	return c.conn.Invoke(ctx, methodForceFinalize.Full(), req, nil)
}

// NewStorageWorkerClient creates a new gRPC transaction scheduler
// client service.
func NewStorageWorkerClient(c *grpc.ClientConn) StorageWorker {
	return &storageWorkerClient{c}
}
