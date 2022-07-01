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
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("RuntimeClient")

	// methodSubmitTx is the SubmitTx method.
	methodSubmitTx = serviceName.NewMethod("SubmitTx", SubmitTxRequest{})
	// methodSubmitTxMeta is the SubmitTxMeta method.
	methodSubmitTxMeta = serviceName.NewMethod("SubmitTxMeta", SubmitTxRequest{})
	// methodSubmitTxNoWait is the SubmitTxNoWait method.
	methodSubmitTxNoWait = serviceName.NewMethod("SubmitTxNoWait", SubmitTxRequest{})
	// methodCheckTx is the CheckTx method.
	methodCheckTx = serviceName.NewMethod("CheckTx", CheckTxRequest{})
	// methodGetGenesisBlock is the GetGenesisBlock method.
	methodGetGenesisBlock = serviceName.NewMethod("GetGenesisBlock", common.Namespace{})
	// methodGetBlock is the GetBlock method.
	methodGetBlock = serviceName.NewMethod("GetBlock", GetBlockRequest{})
	// methodGetLastRetainedBlock is the GetLastRetainedBlock method.
	methodGetLastRetainedBlock = serviceName.NewMethod("GetLastRetainedBlock", common.Namespace{})
	// methodGetTransactions is the GetTransactions method.
	methodGetTransactions = serviceName.NewMethod("GetTransactions", GetTransactionsRequest{})
	// methodGetTransactionsWithResults is the GetTransactionsWithResults method.
	methodGetTransactionsWithResults = serviceName.NewMethod("GetTransactionsWithResults", GetTransactionsRequest{})
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", GetEventsRequest{})
	// methodQuery is the Query method.
	methodQuery = serviceName.NewMethod("Query", QueryRequest{})

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
				MethodName: methodSubmitTxMeta.ShortName(),
				Handler:    handlerSubmitTxMeta,
			},
			{
				MethodName: methodSubmitTxNoWait.ShortName(),
				Handler:    handlerSubmitTxNoWait,
			},
			{
				MethodName: methodCheckTx.ShortName(),
				Handler:    handlerCheckTx,
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
				MethodName: methodGetLastRetainedBlock.ShortName(),
				Handler:    handlerGetLastRetainedBlock,
			},
			{
				MethodName: methodGetTransactions.ShortName(),
				Handler:    handlerGetTransactions,
			},
			{
				MethodName: methodGetTransactionsWithResults.ShortName(),
				Handler:    handlerGetTransactionsWithResults,
			},
			{
				MethodName: methodGetEvents.ShortName(),
				Handler:    handlerGetEvents,
			},
			{
				MethodName: methodQuery.ShortName(),
				Handler:    handlerQuery,
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

func handlerSubmitTx(
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

func handlerSubmitTxMeta(
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
		return srv.(RuntimeClient).SubmitTxMeta(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxMeta.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).SubmitTxMeta(ctx, req.(*SubmitTxRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerSubmitTxNoWait(
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
		return nil, srv.(RuntimeClient).SubmitTxNoWait(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxNoWait.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(RuntimeClient).SubmitTxNoWait(ctx, req.(*SubmitTxRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerCheckTx(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq CheckTxRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(RuntimeClient).CheckTx(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodCheckTx.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(RuntimeClient).CheckTx(ctx, req.(*CheckTxRequest))
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

func handlerGetGenesisBlock(
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

func handlerGetBlock(
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

func handlerGetLastRetainedBlock(
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
		rsp, err := srv.(RuntimeClient).GetLastRetainedBlock(ctx, runtimeID)
		return rsp, errorWrapNotFound(err)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLastRetainedBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		rsp, err := srv.(RuntimeClient).GetLastRetainedBlock(ctx, req.(common.Namespace))
		return rsp, errorWrapNotFound(err)
	}
	return interceptor(ctx, runtimeID, info, handler)
}

func handlerGetTransactions(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetTransactionsRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).GetTransactions(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactions.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).GetTransactions(ctx, req.(*GetTransactionsRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetTransactionsWithResults(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var rq GetTransactionsRequest
	if err := dec(&rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RuntimeClient).GetTransactionsWithResults(ctx, &rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactionsWithResults.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).GetTransactionsWithResults(ctx, req.(*GetTransactionsRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerGetEvents(
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

func handlerQuery( // nolint: revive
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
	conn *grpc.ClientConn
}

func (c *runtimeClient) SubmitTx(ctx context.Context, request *SubmitTxRequest) ([]byte, error) {
	var rsp []byte
	if err := c.conn.Invoke(ctx, methodSubmitTx.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) SubmitTxMeta(ctx context.Context, request *SubmitTxRequest) (*SubmitTxMetaResponse, error) {
	var rsp SubmitTxMetaResponse
	if err := c.conn.Invoke(ctx, methodSubmitTxMeta.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) SubmitTxNoWait(ctx context.Context, request *SubmitTxRequest) error {
	return c.conn.Invoke(ctx, methodSubmitTxNoWait.FullName(), request, nil)
}

func (c *runtimeClient) CheckTx(ctx context.Context, request *CheckTxRequest) error {
	return c.conn.Invoke(ctx, methodCheckTx.FullName(), request, nil)
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

func (c *runtimeClient) GetLastRetainedBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetLastRetainedBlock.FullName(), runtimeID, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTransactions(ctx context.Context, request *GetTransactionsRequest) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetTransactions.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) GetTransactionsWithResults(ctx context.Context, request *GetTransactionsRequest) ([]*TransactionWithResults, error) {
	var rsp []*TransactionWithResults
	if err := c.conn.Invoke(ctx, methodGetTransactionsWithResults.FullName(), request, &rsp); err != nil {
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
		conn: c,
	}
}
