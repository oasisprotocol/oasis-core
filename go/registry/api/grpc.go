package api

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Registry")

	// methodGetEntity is the GetEntity method.
	methodGetEntity = serviceName.NewMethod("GetEntity", IDQuery{})
	// methodGetEntities is the GetEntities method.
	methodGetEntities = serviceName.NewMethod("GetEntities", int64(0))
	// methodGetNode is the GetNode method.
	methodGetNode = serviceName.NewMethod("GetNode", IDQuery{})
	// methodGetNodeByConsensusAddress is the GetNodeByConsensusAddress method.
	methodGetNodeByConsensusAddress = serviceName.NewMethod("GetNodeByConsensusAddress", ConsensusAddressQuery{})
	// methodGetNodeStatus is the GetNodeStatus method.
	methodGetNodeStatus = serviceName.NewMethod("GetNodeStatus", IDQuery{})
	// methodGetNodes is the GetNodes method.
	methodGetNodes = serviceName.NewMethod("GetNodes", int64(0))
	// methodGetRuntime is the GetRuntime method.
	methodGetRuntime = serviceName.NewMethod("GetRuntime", GetRuntimeQuery{})
	// methodGetRuntimes is the GetRuntimes method.
	methodGetRuntimes = serviceName.NewMethod("GetRuntimes", GetRuntimesQuery{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))

	// methodWatchEntities is the WatchEntities method.
	methodWatchEntities = serviceName.NewMethod("WatchEntities", nil)
	// methodWatchNodes is the WatchNodes method.
	methodWatchNodes = serviceName.NewMethod("WatchNodes", nil)
	// methodWatchNodeList is the WatchNodeList method.
	methodWatchNodeList = serviceName.NewMethod("WatchNodeList", nil)
	// methodWatchRuntimes is the WatchRuntimes method.
	methodWatchRuntimes = serviceName.NewMethod("WatchRuntimes", nil)
	// methodWatchEvents is the WatchEvents method.
	methodWatchEvents = serviceName.NewMethod("WatchEvents", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetEntity.ShortName(),
				Handler:    handlerGetEntity,
			},
			{
				MethodName: methodGetEntities.ShortName(),
				Handler:    handlerGetEntities,
			},
			{
				MethodName: methodGetNode.ShortName(),
				Handler:    handlerGetNode,
			},
			{
				MethodName: methodGetNodeByConsensusAddress.ShortName(),
				Handler:    handlerGetNodeByConsensusAddress,
			},
			{
				MethodName: methodGetNodeStatus.ShortName(),
				Handler:    handlerGetNodeStatus,
			},
			{
				MethodName: methodGetNodes.ShortName(),
				Handler:    handlerGetNodes,
			},
			{
				MethodName: methodGetRuntime.ShortName(),
				Handler:    handlerGetRuntime,
			},
			{
				MethodName: methodGetRuntimes.ShortName(),
				Handler:    handlerGetRuntimes,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodGetEvents.ShortName(),
				Handler:    handlerGetEvents,
			},
			{
				MethodName: methodConsensusParameters.ShortName(),
				Handler:    handlerConsensusParameters,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchEntities.ShortName(),
				Handler:       handlerWatchEntities,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchNodes.ShortName(),
				Handler:       handlerWatchNodes,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchNodeList.ShortName(),
				Handler:       handlerWatchNodeList,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchRuntimes.ShortName(),
				Handler:       handlerWatchRuntimes,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchEvents.ShortName(),
				Handler:       handlerWatchEvents,
				ServerStreams: true,
			},
		},
	}
)

func handlerGetEntity(
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
		FullMethod: methodGetEntity.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEntity(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetEntities(
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
		FullMethod: methodGetEntities.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEntities(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetNode(
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
		FullMethod: methodGetNode.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNode(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetNodeByConsensusAddress(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query ConsensusAddressQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetNodeByConsensusAddress(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNodeByConsensusAddress.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodeByConsensusAddress(ctx, req.(*ConsensusAddressQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetNodeStatus(
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
		FullMethod: methodGetNodeStatus.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodeStatus(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetNodes(
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
		FullMethod: methodGetNodes.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetNodes(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetRuntime(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query GetRuntimeQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetRuntime(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetRuntime.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetRuntime(ctx, req.(*GetRuntimeQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetRuntimes(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query GetRuntimesQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetRuntimes(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetRuntimes.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetRuntimes(ctx, req.(*GetRuntimesQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

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

func handlerGetEvents(
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
		return srv.(Backend).GetEvents(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEvents.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEvents(ctx, req.(int64))
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

func handlerWatchEvents(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEvents(ctx)
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

// Client is a gRPC registry client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC registry client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{
		conn: c,
	}
}

func (c *Client) GetEntity(ctx context.Context, query *IDQuery) (*entity.Entity, error) {
	var rsp entity.Entity
	if err := c.conn.Invoke(ctx, methodGetEntity.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetEntities(ctx context.Context, height int64) ([]*entity.Entity, error) {
	var rsp []*entity.Entity
	if err := c.conn.Invoke(ctx, methodGetEntities.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *Client) WatchEntities(ctx context.Context) (<-chan *EntityEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEntities.FullName())
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

func (c *Client) GetNode(ctx context.Context, query *IDQuery) (*node.Node, error) {
	var rsp node.Node
	if err := c.conn.Invoke(ctx, methodGetNode.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetNodeByConsensusAddress(ctx context.Context, query *ConsensusAddressQuery) (*node.Node, error) {
	var rsp node.Node
	if err := c.conn.Invoke(ctx, methodGetNodeByConsensusAddress.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetNodeStatus(ctx context.Context, query *IDQuery) (*NodeStatus, error) {
	var rsp NodeStatus
	if err := c.conn.Invoke(ctx, methodGetNodeStatus.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetNodes(ctx context.Context, height int64) ([]*node.Node, error) {
	var rsp []*node.Node
	if err := c.conn.Invoke(ctx, methodGetNodes.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *Client) WatchNodes(ctx context.Context) (<-chan *NodeEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], methodWatchNodes.FullName())
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

func (c *Client) WatchNodeList(ctx context.Context) (<-chan *NodeList, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[2], methodWatchNodeList.FullName())
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

func (c *Client) GetRuntime(ctx context.Context, query *GetRuntimeQuery) (*Runtime, error) {
	var rsp Runtime
	if err := c.conn.Invoke(ctx, methodGetRuntime.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetRuntimes(ctx context.Context, query *GetRuntimesQuery) ([]*Runtime, error) {
	var rsp []*Runtime
	if err := c.conn.Invoke(ctx, methodGetRuntimes.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *Client) WatchRuntimes(ctx context.Context) (<-chan *Runtime, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[3], methodWatchRuntimes.FullName())
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

func (c *Client) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetEvents(ctx context.Context, height int64) ([]*Event, error) {
	var rsp []*Event
	if err := c.conn.Invoke(ctx, methodGetEvents.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *Client) WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEvents.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Event)
	go func() {
		defer close(ch)

		for {
			var ev Event
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

func (c *Client) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var rsp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) Cleanup() {
}
