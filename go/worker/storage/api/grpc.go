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

// Client is a gRPC worker storage client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC worker storage client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{
		conn: c,
	}
}

func (c *Client) GetLastSyncedRound(ctx context.Context, req *GetLastSyncedRoundRequest) (*GetLastSyncedRoundResponse, error) {
	var rsp GetLastSyncedRoundResponse
	if err := c.conn.Invoke(ctx, methodGetLastSyncedRound.FullName(), req, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) PauseCheckpointer(ctx context.Context, req *PauseCheckpointerRequest) error {
	return c.conn.Invoke(ctx, methodPauseCheckpointer.FullName(), req, nil)
}
