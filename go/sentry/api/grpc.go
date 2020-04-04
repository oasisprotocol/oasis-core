package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Sentry")

	// methodGetAddresses is the GetAddresses method.
	methodGetAddresses = serviceName.NewMethod("GetAddresses", nil)

	// methodSetUpstreamTLSCertificates is the SetUpstreamTLSCertificates method.
	methodSetUpstreamTLSCertificates = serviceName.NewMethod("SetUpstreamTLSCertificates", [][]byte{})

	// methodGetUpstreamTLSCertificates is the GetUpstreamTLSCertificates method.
	methodGetUpstreamTLSCertificates = serviceName.NewMethod("GetUpstreamTLSCertificates", nil)

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
				MethodName: methodSetUpstreamTLSCertificates.ShortName(),
				Handler:    handlerSetUpstreamTLSCertificates,
			},
			{
				MethodName: methodGetUpstreamTLSCertificates.ShortName(),
				Handler:    handlerGetUpstreamTLSCertificates,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerGetAddresses( // nolint: golint
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

func handlerSetUpstreamTLSCertificates( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req [][]byte
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).SetUpstreamTLSCertificates(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSetUpstreamTLSCertificates.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).SetUpstreamTLSCertificates(ctx, *req.(*[][]byte))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerGetUpstreamTLSCertificates( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).GetUpstreamTLSCertificates(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetUpstreamTLSCertificates.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetUpstreamTLSCertificates(ctx)
	}
	return interceptor(ctx, nil, info, handler)
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

func (c *sentryClient) SetUpstreamTLSCertificates(ctx context.Context, certs [][]byte) error {
	if err := c.conn.Invoke(ctx, methodSetUpstreamTLSCertificates.FullName(), certs, nil); err != nil {
		return err
	}
	return nil
}

func (c *sentryClient) GetUpstreamTLSCertificates(ctx context.Context) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetUpstreamTLSCertificates.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

// NewSentryClient creates a new gRPC sentry client service.
func NewSentryClient(c *grpc.ClientConn) Backend {
	return &sentryClient{c}
}
