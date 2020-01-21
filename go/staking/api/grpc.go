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

	// methodTotalSupply is the TotalSupply method.
	methodTotalSupply = serviceName.NewMethod("TotalSupply", int64(0))
	// methodCommonPool is the CommonPool method.
	methodCommonPool = serviceName.NewMethod("CommonPool", int64(0))
	// methodThreshold is the Threshold method.
	methodThreshold = serviceName.NewMethod("Threshold", ThresholdQuery{})
	// methodAccounts is the Accounts method.
	methodAccounts = serviceName.NewMethod("Accounts", int64(0))
	// methodAccountInfo is the AccountInfo method.
	methodAccountInfo = serviceName.NewMethod("AccountInfo", OwnerQuery{})
	// methodDebondingDelegations is the DebondingDelegations method.
	methodDebondingDelegations = serviceName.NewMethod("DebondingDelegations", OwnerQuery{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))

	// methodWatchTransfers is the WatchTransfers method.
	methodWatchTransfers = serviceName.NewMethod("WatchTransfers", nil)
	// methodWatchBurns is the WatchBurns method.
	methodWatchBurns = serviceName.NewMethod("WatchBurns", nil)
	// methodWatchEscrows is the WatchEscrows method.
	methodWatchEscrows = serviceName.NewMethod("WatchEscrows", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodTotalSupply.ShortName(),
				Handler:    handlerTotalSupply,
			},
			{
				MethodName: methodCommonPool.ShortName(),
				Handler:    handlerCommonPool,
			},
			{
				MethodName: methodThreshold.ShortName(),
				Handler:    handlerThreshold,
			},
			{
				MethodName: methodAccounts.ShortName(),
				Handler:    handlerAccounts,
			},
			{
				MethodName: methodAccountInfo.ShortName(),
				Handler:    handlerAccountInfo,
			},
			{
				MethodName: methodDebondingDelegations.ShortName(),
				Handler:    handlerDebondingDelegations,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchTransfers.ShortName(),
				Handler:       handlerWatchTransfers,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchBurns.ShortName(),
				Handler:       handlerWatchBurns,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchEscrows.ShortName(),
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
		FullMethod: methodTotalSupply.FullName(),
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
		FullMethod: methodCommonPool.FullName(),
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
		FullMethod: methodThreshold.FullName(),
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
		FullMethod: methodAccounts.FullName(),
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
		FullMethod: methodAccountInfo.FullName(),
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
		FullMethod: methodDebondingDelegations.FullName(),
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
		FullMethod: methodStateToGenesis.FullName(),
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
	if err := c.conn.Invoke(ctx, methodTotalSupply.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodCommonPool.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) Threshold(ctx context.Context, query *ThresholdQuery) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodThreshold.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error) {
	var rsp []signature.PublicKey
	if err := c.conn.Invoke(ctx, methodAccounts.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) AccountInfo(ctx context.Context, query *OwnerQuery) (*Account, error) {
	var rsp Account
	if err := c.conn.Invoke(ctx, methodAccountInfo.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) DebondingDelegations(ctx context.Context, query *OwnerQuery) (map[signature.PublicKey][]*DebondingDelegation, error) {
	var rsp map[signature.PublicKey][]*DebondingDelegation
	if err := c.conn.Invoke(ctx, methodDebondingDelegations.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) WatchTransfers(ctx context.Context) (<-chan *TransferEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchTransfers.FullName())
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

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], methodWatchBurns.FullName())
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

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[2], methodWatchEscrows.FullName())
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
