package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("StorageWorker")

	// methodGetLastSyncedRound is the GetLastSyncedRound method.
	methodGetLastSyncedRound = serviceName.NewMethod("GetLastSyncedRound", &GetLastSyncedRoundRequest{})
	// methodPauseCheckpointer is the PauseCheckpointer method.
	methodPauseCheckpointer = serviceName.NewMethod("PauseCheckpointer", &PauseCheckpointerRequest{})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*StorageWorker)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetLastSyncedRound.ShortName(),
				Handler:    handlerGetLastSyncedRound,
			},
			{
				MethodName: methodPauseCheckpointer.ShortName(),
				Handler:    handlerPauseCheckpointer,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerGetLastSyncedRound(
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
		FullMethod: methodGetLastSyncedRound.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageWorker).GetLastSyncedRound(ctx, req.(*GetLastSyncedRoundRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerPauseCheckpointer(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(PauseCheckpointerRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(StorageWorker).PauseCheckpointer(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodPauseCheckpointer.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(StorageWorker).PauseCheckpointer(ctx, req.(*PauseCheckpointerRequest))
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
	if err := c.conn.Invoke(ctx, methodGetLastSyncedRound.FullName(), req, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *storageWorkerClient) PauseCheckpointer(ctx context.Context, req *PauseCheckpointerRequest) error {
	return c.conn.Invoke(ctx, methodPauseCheckpointer.FullName(), req, nil)
}

// NewStorageWorkerClient creates a new gRPC transaction scheduler
// client service.
func NewStorageWorkerClient(c *grpc.ClientConn) StorageWorker {
	return &storageWorkerClient{c}
}
