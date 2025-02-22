package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("KeyManager")

	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
		},
	}
)

func handlerStateToGenesis(
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
		return srv.(Backend).StateToGenesis(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateToGenesis.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

// RegisterService registers a new keymanager backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)

	secrets.RegisterService(server, service.Secrets())
	churp.RegisterService(server, service.Churp())
}

// Client is a gRPC keymanager client.
type Client struct {
	conn *grpc.ClientConn
}

// NewKeymanagerClient creates a new gRPC keymanager client.
func NewKeymanagerClient(c *grpc.ClientConn) Backend {
	return &Client{
		conn: c,
	}
}

func (c *Client) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var resp *Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) Secrets() secrets.Backend {
	return secrets.NewClient(c.conn)
}

func (c *Client) Churp() churp.Backend {
	return churp.NewClient(c.conn)
}
