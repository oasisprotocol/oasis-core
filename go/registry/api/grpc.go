package api

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Registry")

	// methodGetEntity is the name of the GetEntity method.
	methodGetEntity = serviceName.NewMethodName("GetEntity")
	// methodGetEntities is the name of the GetEntities method.
	methodGetEntities = serviceName.NewMethodName("GetEntities")
	// methodGetNode is the name of the GetNode method.
	methodGetNode = serviceName.NewMethodName("GetNode")
	// methodGetNodeStatus is the name of the GetNodeStatus method.
	methodGetNodeStatus = serviceName.NewMethodName("GetNodeStatus")
	// methodGetNodes is the name of the GetNodes method.
	methodGetNodes = serviceName.NewMethodName("GetNodes")
	// methodGetRuntime is the name of the GetRuntime method.
	methodGetRuntime = serviceName.NewMethodName("GetRuntime")
	// methodGetRuntimes is the name of the GetRuntimes method.
	methodGetRuntimes = serviceName.NewMethodName("GetRuntimes")
	// methodGetNodeList is the name of the GetNodeList method.
	methodGetNodeList = serviceName.NewMethodName("GetNodeList")
	// methodStateToGenesis is the name of the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethodName("StateToGenesis")

	// methodWatchEntities is the name of the WatchEntities method.
	methodWatchEntities = serviceName.NewMethodName("WatchEntities")
	// methodWatchNodes is the name of the WatchNodes method.
	methodWatchNodes = serviceName.NewMethodName("WatchNodes")
	// methodWatchNodeList is the name of the WatchNodeList method.
	methodWatchNodeList = serviceName.NewMethodName("WatchNodeList")
	// methodWatchRuntimes is the name of the WatchRuntimes method.
	methodWatchRuntimes = serviceName.NewMethodName("WatchRuntimes")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetEntity.Short(),
				Handler:    handlerGetEntity,
			},
			{
				MethodName: methodGetEntities.Short(),
				Handler:    handlerGetEntities,
			},
			{
				MethodName: methodGetNode.Short(),
				Handler:    handlerGetNode,
			},
			{
				MethodName: methodGetNodeStatus.Short(),
				Handler:    handlerGetNodeStatus,
			},
			{
				MethodName: methodGetNodes.Short(),
				Handler:    handlerGetNodes,
			},
			{
				MethodName: methodGetRuntime.Short(),
				Handler:    handlerGetRuntime,
			},
			{
				MethodName: methodGetRuntimes.Short(),
				Handler:    handlerGetRuntimes,
			},
			{
				MethodName: methodGetNodeList.Short(),
				Handler:    handlerGetNodeList,
			},
			{
				MethodName: methodStateToGenesis.Short(),
				Handler:    handlerStateToGenesis,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchEntities.Short(),
				Handler:       handlerWatchEntities,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchNodes.Short(),
				Handler:       handlerWatchNodes,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchNodeList.Short(),
				Handler:       handlerWatchNodeList,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchRuntimes.Short(),
				Handler:       handlerWatchRuntimes,
				ServerStreams: true,
			},
		},
	}
)

func handlerGetEntity( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query IDQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetEntity(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEntity.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEntity(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetEntities( // nolint: golint
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
		return srv.(Backend).GetEntities(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEntities.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEntities(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetNode( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query IDQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetNode(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNode.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNode(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetNodeStatus( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query IDQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetNodeStatus(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNodeStatus.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodeStatus(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetNodes( // nolint: golint
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
		return srv.(Backend).GetNodes(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNodes.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodes(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetRuntime( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query IDQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetRuntime(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetRuntime.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetRuntime(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetRuntimes( // nolint: golint
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
		return srv.(Backend).GetRuntimes(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetRuntimes.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetRuntimes(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetNodeList( // nolint: golint
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
		return srv.(Backend).GetNodeList(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNodeList.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodeList(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerStateToGenesis( // nolint: golint
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
		FullMethod: methodStateToGenesis.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerWatchEntities(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEntities(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchNodes(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchNodes(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchNodeList(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchNodeList(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchRuntimes(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchRuntimes(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new registry backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type registryClient struct {
	conn *grpc.ClientConn
}

func (c *registryClient) GetEntity(ctx context.Context, query *IDQuery) (*entity.Entity, error) {
	var rsp entity.Entity
	if err := c.conn.Invoke(ctx, methodGetEntity.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	var rsp []*entity.Entity
	if err := c.conn.Invoke(ctx, methodGetEntities.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *registryClient) WatchEntities(ctx context.Context) (<-chan *EntityEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEntities.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *EntityEvent)
	go func() {
		defer close(ch)

		for {
			var ev EntityEvent
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *registryClient) GetNode(ctx context.Context, query *IDQuery) (*node.Node, error) {
	var rsp node.Node
	if err := c.conn.Invoke(ctx, methodGetNode.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) GetNodeStatus(ctx context.Context, query *IDQuery) (*NodeStatus, error) {
	var rsp NodeStatus
	if err := c.conn.Invoke(ctx, methodGetNodeStatus.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	var rsp []*node.Node
	if err := c.conn.Invoke(ctx, methodGetNodes.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *registryClient) WatchNodes(ctx context.Context) (<-chan *NodeEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], methodWatchNodes.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *NodeEvent)
	go func() {
		defer close(ch)

		for {
			var ev NodeEvent
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *registryClient) WatchNodeList(ctx context.Context) (<-chan *NodeList, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[2], methodWatchNodeList.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *NodeList)
	go func() {
		defer close(ch)

		for {
			var ev NodeList
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *registryClient) GetRuntime(ctx context.Context, query *IDQuery) (*Runtime, error) {
	var rsp Runtime
	if err := c.conn.Invoke(ctx, methodGetRuntime.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) GetRuntimes(ctx context.Context, height int64) ([]*Runtime, error) {
	var rsp []*Runtime
	if err := c.conn.Invoke(ctx, methodGetRuntimes.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *registryClient) GetNodeList(ctx context.Context, height int64) (*NodeList, error) {
	var rsp NodeList
	if err := c.conn.Invoke(ctx, methodGetNodeList.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) WatchRuntimes(ctx context.Context) (<-chan *Runtime, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[3], methodWatchRuntimes.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Runtime)
	go func() {
		defer close(ch)

		for {
			var ev Runtime
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *registryClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *registryClient) Cleanup() {
}

// NewRegistryClient creates a new gRPC registry client service.
func NewRegistryClient(c *grpc.ClientConn) Backend {
	return &registryClient{c}
}
