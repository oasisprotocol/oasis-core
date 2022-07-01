package api

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Sentry")

	// methodGetAddresses is the GetAddresses method.
	methodGetAddresses = serviceName.NewMethod("GetAddresses", nil)

	// methodSetUpstreamTLSPubKeys is the SetUpstreamTLSPubKeys method.
	methodSetUpstreamTLSPubKeys = serviceName.NewMethod("SetUpstreamTLSPubKeys", []signature.PublicKey{})

	// methodGetUpstreamTLSPubKeys is the GetUpstreamTLSPubKeys method.
	methodGetUpstreamTLSPubKeys = serviceName.NewMethod("GetUpstreamTLSPubKeys", nil)

	// methodUpdatePolicies is the UpdatePolicies method.
	methodUpdatePolicies = serviceName.NewMethod("UpdatePolicies", ServicePolicies{})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetAddresses.ShortName(),
				Handler:    handlerGetAddresses,
			},
			{
				MethodName: methodSetUpstreamTLSPubKeys.ShortName(),
				Handler:    handlerSetUpstreamTLSPubKeys,
			},
			{
				MethodName: methodGetUpstreamTLSPubKeys.ShortName(),
				Handler:    handlerGetUpstreamTLSPubKeys,
			},
			{
				MethodName: methodUpdatePolicies.ShortName(),
				Handler:    handlerUpdatePolicies,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerGetAddresses(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).GetAddresses(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetAddresses.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetAddresses(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerSetUpstreamTLSPubKeys(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req []signature.PublicKey
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).SetUpstreamTLSPubKeys(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSetUpstreamTLSPubKeys.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).SetUpstreamTLSPubKeys(ctx, *req.(*[]signature.PublicKey))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerGetUpstreamTLSPubKeys(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).GetUpstreamTLSPubKeys(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetUpstreamTLSPubKeys.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetUpstreamTLSPubKeys(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerUpdatePolicies(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req ServicePolicies
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).UpdatePolicies(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodUpdatePolicies.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).UpdatePolicies(ctx, *req.(*ServicePolicies))
	}
	return interceptor(ctx, &req, info, handler)
}

// RegisterService registers a new sentry service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type sentryClient struct {
	conn *grpc.ClientConn
}

func (c *sentryClient) GetAddresses(ctx context.Context) (*SentryAddresses, error) {
	var rsp SentryAddresses
	if err := c.conn.Invoke(ctx, methodGetAddresses.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *sentryClient) SetUpstreamTLSPubKeys(ctx context.Context, pubKeys []signature.PublicKey) error {
	if err := c.conn.Invoke(ctx, methodSetUpstreamTLSPubKeys.FullName(), pubKeys, nil); err != nil {
		return err
	}
	return nil
}

func (c *sentryClient) GetUpstreamTLSPubKeys(ctx context.Context) ([]signature.PublicKey, error) {
	var rsp []signature.PublicKey
	if err := c.conn.Invoke(ctx, methodGetUpstreamTLSPubKeys.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *sentryClient) UpdatePolicies(ctx context.Context, pols ServicePolicies) error {
	if err := c.conn.Invoke(ctx, methodUpdatePolicies.FullName(), pols, nil); err != nil {
		return err
	}
	return nil
}

// NewSentryClient creates a new gRPC sentry client service.
func NewSentryClient(c *grpc.ClientConn) Backend {
	return &sentryClient{c}
}
