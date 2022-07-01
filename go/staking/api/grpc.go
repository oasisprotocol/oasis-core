package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Staking")

	// methodTokenSymbol is the TokenSymbol method.
	methodTokenSymbol = serviceName.NewMethod("TokenSymbol", nil)
	// methodTokenValueExponent is the TokenValueExponent method.
	methodTokenValueExponent = serviceName.NewMethod("TokenValueExponent", nil)
	// methodTotalSupply is the TotalSupply method.
	methodTotalSupply = serviceName.NewMethod("TotalSupply", int64(0))
	// methodCommonPool is the CommonPool method.
	methodCommonPool = serviceName.NewMethod("CommonPool", int64(0))
	// methodLastBlockFees is the LastBlockFees method.
	methodLastBlockFees = serviceName.NewMethod("LastBlockFees", int64(0))
	// methodGovernanceDeposits is the GovernanceDeposits method.
	methodGovernanceDeposits = serviceName.NewMethod("GovernanceDeposits", int64(0))
	// methodThreshold is the Threshold method.
	methodThreshold = serviceName.NewMethod("Threshold", ThresholdQuery{})
	// methodAddresses is the Addresses method.
	methodAddresses = serviceName.NewMethod("Addresses", int64(0))
	// methodAccount is the Account method.
	methodAccount = serviceName.NewMethod("Account", OwnerQuery{})
	// methodDelegationsFor is the DelegationsFor method.
	methodDelegationsFor = serviceName.NewMethod("DelegationsFor", OwnerQuery{})
	// methodDelegationInfosFor is the DelegationInfosFor method.
	methodDelegationInfosFor = serviceName.NewMethod("DelegationInfosFor", OwnerQuery{})
	// methodDelegationsTo is the DelegationsTo method.
	methodDelegationsTo = serviceName.NewMethod("DelegationsTo", OwnerQuery{})
	// methodDebondingDelegationsFor is the DebondingDelegationsFor method.
	methodDebondingDelegationsFor = serviceName.NewMethod("DebondingDelegationsFor", OwnerQuery{})
	// methodDebondingDelegationInfosFor is the DebondingDelegationInfosFor method.
	methodDebondingDelegationInfosFor = serviceName.NewMethod("DebondingDelegationInfosFor", OwnerQuery{})
	// methodDebondingDelegationsTo is the DebondingDelegationsTo method.
	methodDebondingDelegationsTo = serviceName.NewMethod("DebondingDelegationsTo", OwnerQuery{})
	// methodAllowance is the Allowance method.
	methodAllowance = serviceName.NewMethod("Allowance", AllowanceQuery{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", int64(0))

	// methodWatchEvents is the WatchEvents method.
	methodWatchEvents = serviceName.NewMethod("WatchEvents", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodTokenSymbol.ShortName(),
				Handler:    handlerTokenSymbol,
			},
			{
				MethodName: methodTokenValueExponent.ShortName(),
				Handler:    handlerTokenValueExponent,
			},
			{
				MethodName: methodTotalSupply.ShortName(),
				Handler:    handlerTotalSupply,
			},
			{
				MethodName: methodCommonPool.ShortName(),
				Handler:    handlerCommonPool,
			},
			{
				MethodName: methodLastBlockFees.ShortName(),
				Handler:    handlerLastBlockFees,
			},
			{
				MethodName: methodGovernanceDeposits.ShortName(),
				Handler:    handlerGovernanceDeposits,
			},
			{
				MethodName: methodThreshold.ShortName(),
				Handler:    handlerThreshold,
			},
			{
				MethodName: methodAddresses.ShortName(),
				Handler:    handlerAddresses,
			},
			{
				MethodName: methodAccount.ShortName(),
				Handler:    handlerAccount,
			},
			{
				MethodName: methodDelegationsFor.ShortName(),
				Handler:    handlerDelegationsFor,
			},
			{
				MethodName: methodDelegationInfosFor.ShortName(),
				Handler:    handlerDelegationInfosFor,
			},
			{
				MethodName: methodDelegationsTo.ShortName(),
				Handler:    handlerDelegationsTo,
			},
			{
				MethodName: methodDebondingDelegationsFor.ShortName(),
				Handler:    handlerDebondingDelegationsFor,
			},
			{
				MethodName: methodDebondingDelegationInfosFor.ShortName(),
				Handler:    handlerDebondingDelegationInfosFor,
			},
			{
				MethodName: methodDebondingDelegationsTo.ShortName(),
				Handler:    handlerDebondingDelegationsTo,
			},
			{
				MethodName: methodAllowance.ShortName(),
				Handler:    handlerAllowance,
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
				StreamName:    methodWatchEvents.ShortName(),
				Handler:       handlerWatchEvents,
				ServerStreams: true,
			},
		},
	}
)

func handlerTokenSymbol(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).TokenSymbol(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodTokenSymbol.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).TokenSymbol(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerTokenValueExponent(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).TokenValueExponent(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodTokenValueExponent.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).TokenValueExponent(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerTotalSupply(
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

func handlerCommonPool(
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

func handlerLastBlockFees(
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
		return srv.(Backend).LastBlockFees(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodLastBlockFees.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).LastBlockFees(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGovernanceDeposits(
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
		return srv.(Backend).GovernanceDeposits(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGovernanceDeposits.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GovernanceDeposits(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerThreshold(
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

func handlerAddresses(
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
		return srv.(Backend).Addresses(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAddresses.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Addresses(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerAccount(
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
		return srv.(Backend).Account(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAccount.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Account(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDelegationsFor(
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
		return srv.(Backend).DelegationsFor(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDelegationsFor.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DelegationsFor(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDelegationInfosFor(
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
		return srv.(Backend).DelegationInfosFor(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDelegationInfosFor.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DelegationInfosFor(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDelegationsTo(
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
		return srv.(Backend).DelegationsTo(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDelegationsTo.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DelegationsTo(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDebondingDelegationsFor(
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
		return srv.(Backend).DebondingDelegationsFor(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDebondingDelegationsFor.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DebondingDelegationsFor(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDebondingDelegationInfosFor(
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
		return srv.(Backend).DebondingDelegationInfosFor(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDebondingDelegationInfosFor.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DebondingDelegationInfosFor(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerDebondingDelegationsTo(
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
		return srv.(Backend).DebondingDelegationsTo(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodDebondingDelegationsTo.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).DebondingDelegationsTo(ctx, req.(*OwnerQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerAllowance(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query AllowanceQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Allowance(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodAllowance.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Allowance(ctx, req.(*AllowanceQuery))
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

// RegisterService registers a new staking backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type stakingClient struct {
	conn *grpc.ClientConn
}

func (c *stakingClient) TokenSymbol(ctx context.Context) (string, error) {
	var rsp string
	if err := c.conn.Invoke(ctx, methodTokenSymbol.FullName(), nil, &rsp); err != nil {
		return "", err
	}
	return rsp, nil
}

func (c *stakingClient) TokenValueExponent(ctx context.Context) (uint8, error) {
	var rsp uint8
	if err := c.conn.Invoke(ctx, methodTokenValueExponent.FullName(), nil, &rsp); err != nil {
		return 0, err
	}
	return rsp, nil
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

func (c *stakingClient) LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodLastBlockFees.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) GovernanceDeposits(ctx context.Context, height int64) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodGovernanceDeposits.FullName(), height, &rsp); err != nil {
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

func (c *stakingClient) Addresses(ctx context.Context, height int64) ([]Address, error) {
	var rsp []Address
	if err := c.conn.Invoke(ctx, methodAddresses.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) Account(ctx context.Context, query *OwnerQuery) (*Account, error) {
	var rsp Account
	if err := c.conn.Invoke(ctx, methodAccount.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) DelegationsFor(ctx context.Context, query *OwnerQuery) (map[Address]*Delegation, error) {
	var rsp map[Address]*Delegation
	if err := c.conn.Invoke(ctx, methodDelegationsFor.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) DelegationInfosFor(ctx context.Context, query *OwnerQuery) (map[Address]*DelegationInfo, error) {
	var rsp map[Address]*DelegationInfo
	if err := c.conn.Invoke(ctx, methodDelegationInfosFor.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) DelegationsTo(ctx context.Context, query *OwnerQuery) (map[Address]*Delegation, error) {
	var rsp map[Address]*Delegation
	if err := c.conn.Invoke(ctx, methodDelegationsTo.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) DebondingDelegationsFor(ctx context.Context, query *OwnerQuery) (map[Address][]*DebondingDelegation, error) {
	var rsp map[Address][]*DebondingDelegation
	if err := c.conn.Invoke(ctx, methodDebondingDelegationsFor.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) DebondingDelegationInfosFor(ctx context.Context, query *OwnerQuery) (map[Address][]*DebondingDelegationInfo, error) {
	var rsp map[Address][]*DebondingDelegationInfo
	if err := c.conn.Invoke(ctx, methodDebondingDelegationInfosFor.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) DebondingDelegationsTo(ctx context.Context, query *OwnerQuery) (map[Address][]*DebondingDelegation, error) {
	var rsp map[Address][]*DebondingDelegation
	if err := c.conn.Invoke(ctx, methodDebondingDelegationsTo.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) Allowance(ctx context.Context, query *AllowanceQuery) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodAllowance.FullName(), query, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var rsp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *stakingClient) GetEvents(ctx context.Context, height int64) ([]*Event, error) {
	var rsp []*Event
	if err := c.conn.Invoke(ctx, methodGetEvents.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *stakingClient) WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error) {
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

func (c *stakingClient) Cleanup() {
}

// NewStakingClient creates a new gRPC staking client service.
func NewStakingClient(c *grpc.ClientConn) Backend {
	return &stakingClient{c}
}
