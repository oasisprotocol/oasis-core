package api

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("RuntimeClient")

	// methodSubmitTx is the SubmitTx method.
	methodSubmitTx = serviceName.NewMethod("SubmitTx", SubmitTxRequest{})
	// methodGetGenesisBlock is the GetGenesisBlock method.
	methodGetGenesisBlock = serviceName.NewMethod("GetGenesisBlock", common.Namespace{})
	// methodGetBlock is the GetBlock method.
	methodGetBlock = serviceName.NewMethod("GetBlock", GetBlockRequest{})
	// methodGetBlockByHash is the GetBlockByHash method.
	methodGetBlockByHash = serviceName.NewMethod("GetBlockByHash", GetBlockByHashRequest{})
	// methodGetTx is the GetTx method.
	methodGetTx = serviceName.NewMethod("GetTx", GetTxRequest{})
	// methodGetTxByBlockHash is the GetTxByBlockHash method.
	methodGetTxByBlockHash = serviceName.NewMethod("GetTxByBlockHash", GetTxByBlockHashRequest{})
	// methodGetTxs is the GetTxs method.
	methodGetTxs = serviceName.NewMethod("GetTxs", GetTxsRequest{})
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", GetEventsRequest{})
	// methodQuery is the Query method.
	methodQuery = serviceName.NewMethod("Query", QueryRequest{})
	// methodQueryTx is the QueryTx method.
	methodQueryTx = serviceName.NewMethod("QueryTx", QueryTxRequest{})
	// methodQueryTxs is the QueryTxs method.
	methodQueryTxs = serviceName.NewMethod("QueryTxs", QueryTxsRequest{})
	// methodWaitBlockIndexed is the WaitBlockIndexed method.
	methodWaitBlockIndexed = serviceName.NewMethod("WaitBlockIndexed", WaitBlockIndexedRequest{})

	// methodWatchBlocks is the WatchBlocks method.
	methodWatchBlocks = serviceName.NewMethod("WatchBlocks", common.Namespace{})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*RuntimeClient)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.ShortName(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodGetGenesisBlock.ShortName(),
				Handler:    handlerGetGenesisBlock,
			},
			{
				MethodName: methodGetBlock.ShortName(),
				Handler:    handlerGetBlock,
			},
			{
				MethodName: methodGetBlockByHash.ShortName(),
				Handler:    handlerGetBlockByHash,
			},
			{
				MethodName: methodGetTx.ShortName(),
				Handler:    handlerGetTx,
			},
			{
				MethodName: methodGetTxByBlockHash.ShortName(),
				Handler:    handlerGetTxByBlockHash,
			},
			{
				MethodName: methodGetTxs.ShortName(),
				Handler:    handlerGetTxs,
			},
			{
				MethodName: methodGetEvents.ShortName(),
				Handler:    handlerGetEvents,
			},
			{
				MethodName: methodQuery.ShortName(),
				Handler:    handlerQuery,
			},
			{
				MethodName: methodQueryTx.ShortName(),
				Handler:    handlerQueryTx,
			},
			{
				MethodName: methodQueryTxs.ShortName(),
				Handler:    handlerQueryTxs,
			},
			{
				MethodName: methodWaitBlockIndexed.ShortName(),
				Handler:    handlerWaitBlockIndexed,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchBlocks.ShortName(),
				Handler:       handlerWatchBlocks,
				ServerStreams: true,
			},
		},
	}
)

func handlerSubmitTx( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq SubmitTxRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).SubmitTx(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTx.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).SubmitTx(ctx, req.(*SubmitTxRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

// wrappedErrNotFound is a wrapped ErrNotFound error so that it corresponds
// to the gRPC NotFound error code. It is required because Rust's gRPC bindings
// do not support fetching error details.
type wrappedErrNotFound struct {
	err error
}

func (w wrappedErrNotFound) Unwrap() error {
	return w.err
}

func (w wrappedErrNotFound) Error() string {
	return w.err.Error()
}

func (w wrappedErrNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, w.err.Error())
}

func errorWrapNotFound(err error) error {
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, roothash.ErrNotFound) {
		return err
	}

	return wrappedErrNotFound{err}
}

func handlerGetGenesisBlock( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var runtimeID common.Namespace
	if err := dec(&runtimeID); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).GetGenesisBlock(ctx, runtimeID)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetGenesisBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetGenesisBlock(ctx, req.(common.Namespace))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, runtimeID, info, handler)
}

func handlerGetBlock( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetBlockRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).GetBlock(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetBlock(ctx, req.(*GetBlockRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetBlockByHash( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetBlockByHashRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).GetBlockByHash(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBlockByHash.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetBlockByHash(ctx, req.(*GetBlockByHashRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetTx( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetTxRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).GetTx(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTx.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetTx(ctx, req.(*GetTxRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetTxByBlockHash( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetTxByBlockHashRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).GetTxByBlockHash(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTxByBlockHash.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetTxByBlockHash(ctx, req.(*GetTxByBlockHashRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetTxs( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetTxsRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).GetTxs(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTxs.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).GetTxs(ctx, req.(*GetTxsRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetEvents( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetEventsRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).GetEvents(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEvents.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).GetEvents(ctx, req.(*GetEventsRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerQuery( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq QueryRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).Query(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodQuery.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).Query(ctx, req.(*QueryRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerQueryTx( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq QueryTxRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		rsp, err := srv.(RuntimeClient).QueryTx(ctx, &rq)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodQueryTx.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).QueryTx(ctx, req.(*QueryTxRequest))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerQueryTxs( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq QueryTxsRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).QueryTxs(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodQueryTxs.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).QueryTxs(ctx, req.(*QueryTxsRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerWaitBlockIndexed( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq WaitBlockIndexedRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(RuntimeClient).WaitBlockIndexed(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitBlockIndexed.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(RuntimeClient).WaitBlockIndexed(ctx, req.(*WaitBlockIndexedRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerWatchBlocks(srv interface{}, stream grpc.ServerStream) error {
	var runtimeID common.Namespace
	if err := stream.RecvMsg(&runtimeID); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(RuntimeClient).WatchBlocks(ctx, runtimeID)
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

// RegisterService registers a new runtime client service with the given gRPC server.
func RegisterService(server *grpc.Server, service RuntimeClient) {
	server.RegisterService(&serviceDesc, service)
}

type runtimeClient struct {
	enclaverpc.Transport

	conn *grpc.ClientConn
}

func (c *runtimeClient) SubmitTx(ctx context.Context, request *SubmitTxRequest) ([]byte, error) {
	var rsp []byte
	if err := c.conn.Invoke(ctx, methodSubmitTx.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetGenesisBlock.FullName(), runtimeID, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetBlock(ctx context.Context, request *GetBlockRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetBlock.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetBlockByHash(ctx context.Context, request *GetBlockByHashRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetBlockByHash.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTx(ctx context.Context, request *GetTxRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodGetTx.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTxByBlockHash(ctx context.Context, request *GetTxByBlockHashRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodGetTxByBlockHash.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTxs(ctx context.Context, request *GetTxsRequest) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetTxs.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) GetEvents(ctx context.Context, request *GetEventsRequest) ([]*Event, error) {
	var rsp []*Event
	if err := c.conn.Invoke(ctx, methodGetEvents.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) Query(ctx context.Context, request *QueryRequest) (*QueryResponse, error) {
	var rsp QueryResponse
	if err := c.conn.Invoke(ctx, methodQuery.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) QueryTx(ctx context.Context, request *QueryTxRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodQueryTx.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) QueryTxs(ctx context.Context, request *QueryTxsRequest) ([]*TxResult, error) {
	var rsp []*TxResult
	if err := c.conn.Invoke(ctx, methodQueryTxs.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) WaitBlockIndexed(ctx context.Context, request *WaitBlockIndexedRequest) error {
	return c.conn.Invoke(ctx, methodWaitBlockIndexed.FullName(), request, nil)
}

func (c *runtimeClient) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
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

	ch := make(chan *roothash.AnnotatedBlock)
	go func() {
		defer close(ch)

		for {
			var blk roothash.AnnotatedBlock
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

// NewRuntimeClient creates a new gRPC runtime client service.
func NewRuntimeClient(c *grpc.ClientConn) RuntimeClient {
	return &runtimeClient{
		Transport: enclaverpc.NewTransportClient(c),
		conn:      c,
	}
}
