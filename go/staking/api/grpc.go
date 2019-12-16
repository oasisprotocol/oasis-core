package api

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Staking")

	// methodTotalSupply is the name of the TotalSupply method.
	methodTotalSupply = serviceName.NewMethodName("TotalSupply")
	// methodCommonPool is the name of the CommonPool method.
	methodCommonPool = serviceName.NewMethodName("CommonPool")
	// methodThreshold is the name of the Threshold method.
	methodThreshold = serviceName.NewMethodName("Threshold")
	// methodAccounts is the name of the Accounts method.
	methodAccounts = serviceName.NewMethodName("Accounts")
	// methodAccountInfo is the name of the AccountInfo method.
	methodAccountInfo = serviceName.NewMethodName("AccountInfo")
	// methodDebondingDelegations is the name of the DebondingDelegations method.
	methodDebondingDelegations = serviceName.NewMethodName("DebondingDelegations")
	// methodStateToGenesis is the name of the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethodName("StateToGenesis")

	// methodWatchTransfers is the name of the WatchTransfers method.
	methodWatchTransfers = serviceName.NewMethodName("WatchTransfers")
	// methodWatchBurns is the name of the WatchBurns method.
	methodWatchBurns = serviceName.NewMethodName("WatchBurns")
	// methodWatchEscrows is the name of the WatchEscrows method.
	methodWatchEscrows = serviceName.NewMethodName("WatchEscrows")

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodTotalSupply.Short(),
				Handler:    handlerTotalSupply,
			},
			{
				MethodName: methodCommonPool.Short(),
				Handler:    handlerCommonPool,
			},
			{
				MethodName: methodThreshold.Short(),
				Handler:    handlerThreshold,
			},
			{
				MethodName: methodAccounts.Short(),
				Handler:    handlerAccounts,
			},
			{
				MethodName: methodAccountInfo.Short(),
				Handler:    handlerAccountInfo,
			},
			{
				MethodName: methodDebondingDelegations.Short(),
				Handler:    handlerDebondingDelegations,
			},
			{
				MethodName: methodStateToGenesis.Short(),
				Handler:    handlerStateToGenesis,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchTransfers.Short(),
				Handler:       handlerWatchTransfers,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchBurns.Short(),
				Handler:       handlerWatchBurns,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchEscrows.Short(),
				Handler:       handlerWatchEscrows,
				ServerStreams: true,
			},
		},
	}
)

func handlerTotalSupply( // nolint: golint
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
		return srv.(Backend).TotalSupply(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodTotalSupply.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).TotalSupply(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerCommonPool( // nolint: golint
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
		return srv.(Backend).CommonPool(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodCommonPool.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).CommonPool(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerThreshold( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query ThresholdQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Threshold(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodThreshold.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Threshold(ctx, req.(*ThresholdQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerAccounts( // nolint: golint
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
		return srv.(Backend).Accounts(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAccounts.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Accounts(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerAccountInfo( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query OwnerQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).AccountInfo(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAccountInfo.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).AccountInfo(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDebondingDelegations( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query OwnerQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).DebondingDelegations(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDebondingDelegations.Full(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DebondingDelegations(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
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

func handlerWatchTransfers(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchTransfers(ctx)
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

func handlerWatchBurns(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchBurns(ctx)
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

func handlerWatchEscrows(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEscrows(ctx)
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

// RegisterService registers a new staking backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type stakingClient struct {
	conn *grpc.ClientConn
}

func (c *stakingClient) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodTotalSupply.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodCommonPool.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) Threshold(ctx context.Context, query *ThresholdQuery) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodThreshold.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error) {
	var rsp []signature.PublicKey
	if err := c.conn.Invoke(ctx, methodAccounts.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) AccountInfo(ctx context.Context, query *OwnerQuery) (*Account, error) {
	var rsp Account
	if err := c.conn.Invoke(ctx, methodAccountInfo.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) DebondingDelegations(ctx context.Context, query *OwnerQuery) (map[signature.PublicKey][]*DebondingDelegation, error) {
	var rsp map[signature.PublicKey][]*DebondingDelegation
	if err := c.conn.Invoke(ctx, methodDebondingDelegations.Full(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.Full(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) WatchTransfers(ctx context.Context) (<-chan *TransferEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchTransfers.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *TransferEvent)
	go func() {
		defer close(ch)

		for {
			var ev TransferEvent
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

func (c *stakingClient) WatchBurns(ctx context.Context) (<-chan *BurnEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], methodWatchBurns.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *BurnEvent)
	go func() {
		defer close(ch)

		for {
			var ev BurnEvent
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

func (c *stakingClient) WatchEscrows(ctx context.Context) (<-chan *EscrowEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[2], methodWatchEscrows.Full())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *EscrowEvent)
	go func() {
		defer close(ch)

		for {
			var ev EscrowEvent
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

func (c *stakingClient) Cleanup() {
}

// NewStakingClient creates a new gRPC staking client service.
func NewStakingClient(c *grpc.ClientConn) Backend {
	return &stakingClient{c}
}
