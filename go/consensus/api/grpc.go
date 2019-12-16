package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Consensus")

	// methodSubmitTx is the name of the SubmitTx method.
	methodSubmitTx = serviceName.NewMethodName("SubmitTx")
	// methodStateToGenesis is the name of the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethodName("StateToGenesis")
	// methodWaitEpoch is the name of the WaitEpoch method.
	methodWaitEpoch = serviceName.NewMethodName("WaitEpoch")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.Short(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodStateToGenesis.Short(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodWaitEpoch.Short(),
				Handler:    handlerWaitEpoch,
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
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).SubmitTx(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTx.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).SubmitTx(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateToGenesis( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var blockHeight int64
	if err := dec(&blockHeight); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).StateToGenesis(ctx, blockHeight)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateToGenesis.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, blockHeight, info, handler)
}

func handlerWaitEpoch( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var epoch epochtime.EpochTime
	if err := dec(&epoch); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).WaitEpoch(ctx, epoch)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitEpoch.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).WaitEpoch(ctx, req.(epochtime.EpochTime))
	}
	return interceptor(ctx, epoch, info, handler)
}

// RegisterService registers a new consensus backend service with the
// given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type consensusClient struct {
	conn *grpc.ClientConn
}

func (c *consensusClient) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.conn.Invoke(ctx, methodSubmitTx.Full(), tx, nil)
}

func (c *consensusClient) StateToGenesis(ctx context.Context, blockHeight int64) (*genesis.Document, error) {
	var rsp genesis.Document
	if err := c.conn.Invoke(ctx, methodStateToGenesis.Full(), blockHeight, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) WaitEpoch(ctx context.Context, epoch epochtime.EpochTime) error {
	return c.conn.Invoke(ctx, methodWaitEpoch.Full(), epoch, nil)
}

// NewConsensusClient creates a new gRPC consensus client service.
func NewConsensusClient(c *grpc.ClientConn) ClientBackend {
	return &consensusClient{c}
}
