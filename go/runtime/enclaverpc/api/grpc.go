package api

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

var (
	errInvalidRequestType = fmt.Errorf("invalid request type")

	// ServiceName is the gRPC service name.
	ServiceName = cmnGrpc.NewServiceName("EnclaveRPC")

	// MethodCallEnclave is the CallEnclave method.
	MethodCallEnclave = ServiceName.NewMethod("CallEnclave", CallEnclaveRequest{}).
				WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*CallEnclaveRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.RuntimeID, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			r, ok := req.(*CallEnclaveRequest)
			if !ok {
				return false, errInvalidRequestType
			}

			endpoint, ok := registeredEndpoints.Load(r.Endpoint)
			if !ok {
				return false, fmt.Errorf("enclaverpc: unsupported endpoint: %s", r.Endpoint)
			}

			return endpoint.(Endpoint).AccessControlRequired(ctx, r)
		})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(ServiceName),
		HandlerType: (*Transport)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: MethodCallEnclave.ShortName(),
				Handler:    handlerCallEnclave,
			},
		},
		Streams: []grpc.StreamDesc{},
	}

	// registeredEndpoints is a map of registered EnclaveRPC endpoints. It maps endpoint names
	// to instances of the Endpoint interface.
	registeredEndpoints sync.Map
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
		FullMethod: MethodCallEnclave.FullName(),
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

// NewEndpoint registers a new EnclaveRPC endpoint.
func NewEndpoint(name string, endpoint Endpoint) {
	if _, isRegistered := registeredEndpoints.Load(name); isRegistered {
		panic(fmt.Errorf("enclaverpc: endpoint already registered: %s", name))
	}
	registeredEndpoints.Store(name, endpoint)
}

type transportClient struct {
	conn *grpc.ClientConn
}

func (c *transportClient) CallEnclave(ctx context.Context, request *CallEnclaveRequest) ([]byte, error) {
	var rsp []byte
	if err := c.conn.Invoke(ctx, MethodCallEnclave.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

// NewTransportClient creates a new EnclaveRPC gRPC transport client service.
func NewTransportClient(c *grpc.ClientConn) Transport {
	return &transportClient{c}
}
