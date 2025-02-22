package churp

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("KeyManager.Churp")

	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))
	// methodStatus is the Status method.
	methodStatus = serviceName.NewMethod("Status", StatusQuery{})
	// methodStatuses is the Statuses method.
	methodStatuses = serviceName.NewMethod("Statuses", registry.NamespaceQuery{})
	// methodAllStatuses is the AllStatuses method.
	methodAllStatuses = serviceName.NewMethod("AllStatuses", int64(0))

	// methodWatchStatuses is the WatchStatuses method.
	methodWatchStatuses = serviceName.NewMethod("WatchStatuses", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodConsensusParameters.ShortName(),
				Handler:    handlerConsensusParameters,
			},
			{
				MethodName: methodStatus.ShortName(),
				Handler:    handlerStatus,
			},
			{
				MethodName: methodStatuses.ShortName(),
				Handler:    handlerStatuses,
			},
			{
				MethodName: methodAllStatuses.ShortName(),
				Handler:    handlerAllStatuses,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchStatuses.ShortName(),
				Handler:       handlerWatchStatuses,
				ServerStreams: true,
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

func handlerConsensusParameters(
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
		return srv.(Backend).ConsensusParameters(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodConsensusParameters.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).ConsensusParameters(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerStatus(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query StatusQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Status(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStatus.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Status(ctx, req.(*StatusQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerStatuses(
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
		return srv.(Backend).Statuses(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStatuses.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Statuses(ctx, req.(*registry.NamespaceQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerAllStatuses(
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
		return srv.(Backend).AllStatuses(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAllStatuses.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).AllStatuses(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerWatchStatuses(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchStatuses(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case stat, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(stat); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new keymanager CHURP backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

// Client is a gRPC key manager CHURP client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC key manager CHURP client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{c}
}

func (c *Client) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var resp *Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var resp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Status(ctx context.Context, query *StatusQuery) (*Status, error) {
	var resp Status
	if err := c.conn.Invoke(ctx, methodStatus.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Statuses(ctx context.Context, query *registry.NamespaceQuery) ([]*Status, error) {
	var resp []*Status
	if err := c.conn.Invoke(ctx, methodStatuses.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) AllStatuses(ctx context.Context, height int64) ([]*Status, error) {
	var resp []*Status
	if err := c.conn.Invoke(ctx, methodAllStatuses.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) WatchStatuses(ctx context.Context) (<-chan *Status, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchStatuses.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Status)
	go func() {
		defer close(ch)

		for {
			var stat Status
			if serr := stream.RecvMsg(&stat); serr != nil {
				return
			}

			select {
			case ch <- &stat:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}
