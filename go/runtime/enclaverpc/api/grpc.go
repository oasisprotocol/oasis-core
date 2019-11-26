package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("EnclaveRPC")

	// methodCallEnclave is the name of the CallEnclave method.
	methodCallEnclave = serviceName.NewMethodName("CallEnclave")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Transport)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodCallEnclave.Short(),
				Handler:    handlerCallEnclave,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerCallEnclave( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req CallEnclaveRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Transport).CallEnclave(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodCallEnclave.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Transport).CallEnclave(ctx, req.(*CallEnclaveRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

// RegisterService registers a new EnclaveRPC transport service with the given gRPC server.
func RegisterService(server *grpc.Server, service Transport) {
	server.RegisterService(&serviceDesc, service)
}

type transportClient struct {
	conn *grpc.ClientConn
}

func (c *transportClient) CallEnclave(ctx context.Context, request *CallEnclaveRequest) ([]byte, error) {
	var rsp []byte
	if err := c.conn.Invoke(ctx, methodCallEnclave.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

// NewTransportClient creates a new gRPC EnclaveRPC transport client service.
func NewTransportClient(c *grpc.ClientConn) Transport {
	return &transportClient{c}
}
