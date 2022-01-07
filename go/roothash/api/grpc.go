package api

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("RootHash")

	// methodGetGenesisBlock is the GetGenesisBlock method.
	methodGetGenesisBlock = serviceName.NewMethod("GetGenesisBlock", RuntimeRequest{})
	// methodGetLatestBlock is the GetLatestBlock method.
	methodGetLatestBlock = serviceName.NewMethod("GetLatestBlock", RuntimeRequest{})
	// methodGetRuntimeState is the GetRuntimeState method.
	methodGetRuntimeState = serviceName.NewMethod("GetRuntimeState", RuntimeRequest{})
	// methodGetLastRoundResults is the GetLastRoundResults method.
	methodGetLastRoundResults = serviceName.NewMethod("GetLastRoundResults", RuntimeRequest{})
	// methodGetIncomingMessageQueueMeta is the GetIncomingMessageQueueMeta method.
	methodGetIncomingMessageQueueMeta = serviceName.NewMethod("GetIncomingMessageQueueMeta", RuntimeRequest{})
	// methodGetIncomingMessageQueue is the GetIncomingMessageQueue method.
	methodGetIncomingMessageQueue = serviceName.NewMethod("GetIncomingMessageQueue", InMessageQueueRequest{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", int64(0))

	// methodWatchBlocks is the WatchBlocks method.
	methodWatchBlocks = serviceName.NewMethod("WatchBlocks", common.Namespace{})
	// methodWatchEvents is the WatchEvents method.
	methodWatchEvents = serviceName.NewMethod("WatchEvents", common.Namespace{})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetGenesisBlock.ShortName(),
				Handler:    handlerGetGenesisBlock,
			},
			{
				MethodName: methodGetLatestBlock.ShortName(),
				Handler:    handlerGetLatestBlock,
			},
			{
				MethodName: methodGetRuntimeState.ShortName(),
				Handler:    handlerGetRuntimeState,
			},
			{
				MethodName: methodGetLastRoundResults.ShortName(),
				Handler:    handlerGetLastRoundResults,
			},
			{
				MethodName: methodGetIncomingMessageQueueMeta.ShortName(),
				Handler:    handlerGetIncomingMessageQueueMeta,
			},
			{
				MethodName: methodGetIncomingMessageQueue.ShortName(),
				Handler:    handlerGetIncomingMessageQueue,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodConsensusParameters.ShortName(),
				Handler:    handlerConsensusParameters,
			},
			{
				MethodName: methodGetEvents.ShortName(),
				Handler:    handlerGetEvents,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchBlocks.ShortName(),
				Handler:       handlerWatchBlocks,
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

func handlerGetGenesisBlock( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq RuntimeRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetGenesisBlock(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetGenesisBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetGenesisBlock(ctx, req.(*RuntimeRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetLatestBlock( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq RuntimeRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetLatestBlock(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLatestBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetLatestBlock(ctx, req.(*RuntimeRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetRuntimeState( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq RuntimeRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetRuntimeState(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetRuntimeState.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetRuntimeState(ctx, req.(*RuntimeRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetLastRoundResults( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq RuntimeRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetLastRoundResults(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLastRoundResults.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetLastRoundResults(ctx, req.(*RuntimeRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetIncomingMessageQueueMeta( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq RuntimeRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetIncomingMessageQueueMeta(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetIncomingMessageQueueMeta.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetIncomingMessageQueueMeta(ctx, req.(*RuntimeRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetIncomingMessageQueue( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq InMessageQueueRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetIncomingMessageQueue(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetIncomingMessageQueue.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetIncomingMessageQueue(ctx, req.(*InMessageQueueRequest))
	}
	return interceptor(ctx, &rq, info, handler)
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
		FullMethod: methodStateToGenesis.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerConsensusParameters( // nolint: golint
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

func handlerGetEvents( // nolint: golint
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

func handlerWatchBlocks(srv interface{}, stream grpc.ServerStream) error {
	var runtimeID common.Namespace
	if err := stream.RecvMsg(&runtimeID); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchBlocks(ctx, runtimeID)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(blk); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchEvents(srv interface{}, stream grpc.ServerStream) error {
	var runtimeID common.Namespace
	if err := stream.RecvMsg(&runtimeID); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEvents(ctx, runtimeID)
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

// RegisterService registers a new roothash service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type roothashClient struct {
	conn *grpc.ClientConn
}

func (c *roothashClient) GetGenesisBlock(ctx context.Context, request *RuntimeRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetGenesisBlock.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetLatestBlock(ctx context.Context, request *RuntimeRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetLatestBlock.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetRuntimeState(ctx context.Context, request *RuntimeRequest) (*RuntimeState, error) {
	var rsp RuntimeState
	if err := c.conn.Invoke(ctx, methodGetRuntimeState.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetLastRoundResults(ctx context.Context, request *RuntimeRequest) (*RoundResults, error) {
	var rsp RoundResults
	if err := c.conn.Invoke(ctx, methodGetLastRoundResults.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetIncomingMessageQueueMeta(ctx context.Context, request *RuntimeRequest) (*message.IncomingMessageQueueMeta, error) {
	var rsp message.IncomingMessageQueueMeta
	if err := c.conn.Invoke(ctx, methodGetIncomingMessageQueueMeta.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetIncomingMessageQueue(ctx context.Context, request *InMessageQueueRequest) ([]*message.IncomingMessage, error) {
	var rsp []*message.IncomingMessage
	if err := c.conn.Invoke(ctx, methodGetIncomingMessageQueue.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *roothashClient) TrackRuntime(ctx context.Context, history BlockHistory) error {
	return ErrInvalidArgument
}

func (c *roothashClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var rsp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *roothashClient) GetEvents(ctx context.Context, height int64) ([]*Event, error) {
	var rsp []*Event
	if err := c.conn.Invoke(ctx, methodGetEvents.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *roothashClient) Cleanup() {
}

func (c *roothashClient) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchBlocks.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(runtimeID); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *AnnotatedBlock)
	go func() {
		defer close(ch)

		for {
			var blk AnnotatedBlock
			if serr := stream.RecvMsg(&blk); serr != nil {
				return
			}

			select {
			case ch <- &blk:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *roothashClient) WatchEvents(ctx context.Context, runtimeID common.Namespace) (<-chan *Event, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], methodWatchEvents.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(runtimeID); err != nil {
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

// NewRootHashClient creates a new gRPC roothash client service.
func NewRootHashClient(c *grpc.ClientConn) Backend {
	return &roothashClient{
		conn: c,
	}
}
