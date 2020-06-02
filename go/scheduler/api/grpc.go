package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Scheduler")

	// methodGetValidators is the GetValidators method.
	methodGetValidators = serviceName.NewMethod("GetValidators", int64(0))
	// methodGetCommittees is the GetCommittees method.
	methodGetCommittees = serviceName.NewMethod("GetCommittees", GetCommitteesRequest{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))

	// methodWatchCommittees is the WatchCommittees method.
	methodWatchCommittees = serviceName.NewMethod("WatchCommittees", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetValidators.ShortName(),
				Handler:    handlerGetValidators,
			},
			{
				MethodName: methodGetCommittees.ShortName(),
				Handler:    handlerGetCommittees,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchCommittees.ShortName(),
				Handler:       handlerWatchCommittees,
				ServerStreams: true,
			},
		},
	}
)

func handlerGetValidators( // nolint: golint
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
		return srv.(Backend).GetValidators(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetValidators.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetValidators(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetCommittees( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req GetCommitteesRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetCommittees(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetCommittees.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetCommittees(ctx, req.(*GetCommitteesRequest))
	}
	return interceptor(ctx, &req, info, handler)
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

func handlerWatchCommittees(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchCommittees(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case c, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(c); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new scheduler service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type schedulerClient struct {
	conn *grpc.ClientConn
}

func (c *schedulerClient) GetValidators(ctx context.Context, height int64) ([]*Validator, error) {
	var rsp []*Validator
	if err := c.conn.Invoke(ctx, methodGetValidators.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *schedulerClient) GetCommittees(ctx context.Context, request *GetCommitteesRequest) ([]*Committee, error) {
	var rsp []*Committee
	if err := c.conn.Invoke(ctx, methodGetCommittees.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *schedulerClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *schedulerClient) WatchCommittees(ctx context.Context) (<-chan *Committee, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchCommittees.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Committee)
	go func() {
		defer close(ch)

		for {
			var ev Committee
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

func (c *schedulerClient) Cleanup() {
}

// NewSchedulerClient creates a new gRPC scheduler client service.
func NewSchedulerClient(c *grpc.ClientConn) Backend {
	return &schedulerClient{c}
}
