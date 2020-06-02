package api

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

var (
	// Make sure this always matches the appropriate method in
	// `keymanager-runtime/src/methods.rs`.
	getPublicKeyRequestMethod = "get_public_key"

	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("KeyManager")

	// methodGetStatus is the GetStatus method.
	methodGetStatus = serviceName.NewMethod("GetStatus", registry.NamespaceQuery{})
	// methodGetStatuses is the GetStatuses method.
	methodGetStatuses = serviceName.NewMethod("GetStatuses", int64(0))

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetStatus.ShortName(),
				Handler:    handlerGetStatus,
			},
			{
				MethodName: methodGetStatuses.ShortName(),
				Handler:    handlerGetStatuses,
			},
		},
	}
)

type enclaveRPCEndpoint struct {
}

// Implements enclaverpc.Endpoint.
func (e *enclaveRPCEndpoint) AccessControlRequired(ctx context.Context, request *enclaverpc.CallEnclaveRequest) (bool, error) {
	// Unpack the payload, get method from Frame.
	var f enclaverpc.Frame
	if err := cbor.Unmarshal(request.Payload, &f); err != nil {
		return false, fmt.Errorf("keymanager: unable to unpack EnclaveRPC frame: %w", err)
	}

	switch f.UntrustedPlaintext {
	case "":
		// Anyone can connect.
		return false, nil
	case getPublicKeyRequestMethod:
		// Anyone can get public keys.
		//
		// Note that this is also checked in the enclave, so if the node lied
		// about what method it's using, we will know.
		return false, nil
	default:
		// Defer to access control to check the policy.
		return true, nil
	}
}

func handlerGetStatus( //nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query registry.NamespaceQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetStatus(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatus.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetStatus(ctx, req.(*registry.NamespaceQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetStatuses( //nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetStatuses(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatuses.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetStatuses(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

// RegisterService registers a new keymanager backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

// KeymanagerClient is a gRPC keymanager client.
type KeymanagerClient struct {
	conn *grpc.ClientConn
}

func (c *KeymanagerClient) GetStatus(ctx context.Context, query *registry.NamespaceQuery) (*Status, error) {
	var resp Status
	if err := c.conn.Invoke(ctx, methodGetStatus.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *KeymanagerClient) GetStatuses(ctx context.Context, height int64) ([]*Status, error) {
	var resp []*Status
	if err := c.conn.Invoke(ctx, methodGetStatuses.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// NewKeymanagerClient creates a new gRPC keymanager client service.
func NewKeymanagerClient(c *grpc.ClientConn) *KeymanagerClient {
	return &KeymanagerClient{c}
}

func init() {
	enclaverpc.NewEndpoint(EnclaveRPCEndpoint, &enclaveRPCEndpoint{})
}
