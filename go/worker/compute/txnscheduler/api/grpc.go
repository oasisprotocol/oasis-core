package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("TransactionScheduler")

	// methodSubmitTx is the name of the SubmitTx method.
	methodSubmitTx = serviceName.NewMethodName("SubmitTx")
	// methodIsTransactionQueued is the name of the IsTransactionQueued method.
	methodIsTransactionQueued = serviceName.NewMethodName("IsTransactionQueued")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*TransactionScheduler)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.Short(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodIsTransactionQueued.Short(),
				Handler:    handlerIsTransactionQueued,
			},
		},
		Streams: []grpc.StreamDesc{},
	}
)

func handlerSubmitTx( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(SubmitTxRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TransactionScheduler).SubmitTx(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTx.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TransactionScheduler).SubmitTx(ctx, req.(*SubmitTxRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerIsTransactionQueued( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(IsTransactionQueuedRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TransactionScheduler).IsTransactionQueued(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodIsTransactionQueued.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TransactionScheduler).IsTransactionQueued(ctx, req.(*IsTransactionQueuedRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

// RegisterService registers a new transaction scheduler service with the
// given gRPC server.
func RegisterService(server *grpc.Server, service TransactionScheduler) {
	server.RegisterService(&serviceDesc, service)
}

type transactionSchedulerClient struct {
	conn *grpc.ClientConn
}

func (c *transactionSchedulerClient) SubmitTx(ctx context.Context, req *SubmitTxRequest) (*SubmitTxResponse, error) {
	rsp := new(SubmitTxResponse)
	if err := c.conn.Invoke(ctx, methodSubmitTx.Full(), req, rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *transactionSchedulerClient) IsTransactionQueued(ctx context.Context, req *IsTransactionQueuedRequest) (*IsTransactionQueuedResponse, error) {
	rsp := new(IsTransactionQueuedResponse)
	if err := c.conn.Invoke(ctx, methodIsTransactionQueued.Full(), req, rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

// NewTransactionSchedulerClient creates a new gRPC transaction scheduler
// client service.
func NewTransactionSchedulerClient(c *grpc.ClientConn) TransactionScheduler {
	return &transactionSchedulerClient{c}
}
