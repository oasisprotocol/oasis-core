package api

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("RuntimeClient")

	// methodSubmitTx is the name of the SubmitTx method.
	methodSubmitTx = serviceName.NewMethodName("SubmitTx")
	// methodGetBlock is the name of the GetBlock method.
	methodGetBlock = serviceName.NewMethodName("GetBlock")
	// methodGetBlockByHash is the name of the GetBlockByHash method.
	methodGetBlockByHash = serviceName.NewMethodName("GetBlockByHash")
	// methodGetTx is the name of the GetTx method.
	methodGetTx = serviceName.NewMethodName("GetTx")
	// methodGetTxByBlockHash is the name of the GetTxByBlockHash method.
	methodGetTxByBlockHash = serviceName.NewMethodName("GetTxByBlockHash")
	// methodGetTxs is the name of the GetTxs method.
	methodGetTxs = serviceName.NewMethodName("GetTxs")
	// methodQueryTx is the name of the QueryTx method.
	methodQueryTx = serviceName.NewMethodName("QueryTx")
	// methodQueryTxs is the name of the QueryTxs method.
	methodQueryTxs = serviceName.NewMethodName("QueryTxs")
	// methodWaitBlockIndexed is the name of the WaitBlockIndexed method.
	methodWaitBlockIndexed = serviceName.NewMethodName("WaitBlockIndexed")

	// methodWatchBlocks is the name of the WatchBlocks method.
	methodWatchBlocks = serviceName.NewMethodName("WatchBlocks")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*RuntimeClient)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.Short(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodGetBlock.Short(),
				Handler:    handlerGetBlock,
			},
			{
				MethodName: methodGetBlockByHash.Short(),
				Handler:    handlerGetBlockByHash,
			},
			{
				MethodName: methodGetTx.Short(),
				Handler:    handlerGetTx,
			},
			{
				MethodName: methodGetTxByBlockHash.Short(),
				Handler:    handlerGetTxByBlockHash,
			},
			{
				MethodName: methodGetTxs.Short(),
				Handler:    handlerGetTxs,
			},
			{
				MethodName: methodQueryTx.Short(),
				Handler:    handlerQueryTx,
			},
			{
				MethodName: methodQueryTxs.Short(),
				Handler:    handlerQueryTxs,
			},
			{
				MethodName: methodWaitBlockIndexed.Short(),
				Handler:    handlerWaitBlockIndexed,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchBlocks.Short(),
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
		FullMethod: methodSubmitTx.Full(),
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
		FullMethod: methodGetBlock.Full(),
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
		FullMethod: methodGetBlockByHash.Full(),
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
		FullMethod: methodGetTx.Full(),
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
		FullMethod: methodGetTxByBlockHash.Full(),
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
		FullMethod: methodGetTxs.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RuntimeClient).GetTxs(ctx, req.(*GetTxsRequest))
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
		FullMethod: methodQueryTx.Full(),
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
		FullMethod: methodQueryTxs.Full(),
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
		FullMethod: methodWaitBlockIndexed.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(RuntimeClient).WaitBlockIndexed(ctx, req.(*WaitBlockIndexedRequest))
	}
	return interceptor(ctx, &rq, info, handler)
}

func handlerWatchBlocks(srv interface{}, stream grpc.ServerStream) error {
	var runtimeID signature.PublicKey
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
	if err := c.conn.Invoke(ctx, methodSubmitTx.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) GetBlock(ctx context.Context, request *GetBlockRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetBlock.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetBlockByHash(ctx context.Context, request *GetBlockByHashRequest) (*block.Block, error) {
	var rsp block.Block
	if err := c.conn.Invoke(ctx, methodGetBlockByHash.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTx(ctx context.Context, request *GetTxRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodGetTx.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTxByBlockHash(ctx context.Context, request *GetTxByBlockHashRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodGetTxByBlockHash.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) GetTxs(ctx context.Context, request *GetTxsRequest) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetTxs.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) QueryTx(ctx context.Context, request *QueryTxRequest) (*TxResult, error) {
	var rsp TxResult
	if err := c.conn.Invoke(ctx, methodQueryTx.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *runtimeClient) QueryTxs(ctx context.Context, request *QueryTxsRequest) ([]*TxResult, error) {
	var rsp []*TxResult
	if err := c.conn.Invoke(ctx, methodQueryTxs.Full(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *runtimeClient) WaitBlockIndexed(ctx context.Context, request *WaitBlockIndexedRequest) error {
	return c.conn.Invoke(ctx, methodWaitBlockIndexed.Full(), request, nil)
}

func (c *runtimeClient) WatchBlocks(ctx context.Context, runtimeID signature.PublicKey) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchBlocks.Full())
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

func (c *runtimeClient) Cleanup() {
}

// NewRuntimeClient creates a new gRPC runtime client service.
func NewRuntimeClient(c *grpc.ClientConn) RuntimeClient {
	return &runtimeClient{
		Transport: enclaverpc.NewTransportClient(c),
		conn:      c,
	}
}
