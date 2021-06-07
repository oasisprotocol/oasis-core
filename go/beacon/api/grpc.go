package api

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Beacon")

	// methodGetBaseEpoch is the GetBaseEpoch method.
	methodGetBaseEpoch = serviceName.NewMethod("GetBaseEpoch", nil)
	// methodGetEpoch is the GetEpoch method.
	methodGetEpoch = serviceName.NewMethod("GetEpoch", int64(0))
	// methodGetFutureEpoch is the GetFutureEpoch method.
	methodGetFutureEpoch = serviceName.NewMethod("GetFutureEpoch", int64(0))
	// methodGetEpochBlock is the GetEpochBlock method.
	methodGetEpochBlock = serviceName.NewMethod("GetEpochBlock", EpochTime(0))
	// methodWaitEpoch is the WaitEpoch method.
	methodWaitEpoch = serviceName.NewMethod("WaitEpoch", EpochTime(0))
	// methodGetBeacon is the GetBeacon method.
	methodGetBeacon = serviceName.NewMethod("GetBeacon", int64(0))
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))
	// methodGetPVSSState is the GetPVSSState method.
	methodGetPVSSState = serviceName.NewMethod("GetPVSSState", nil)

	// methodWatchEpochs is the WatchEpochs method.
	methodWatchEpochs = serviceName.NewMethod("WatchEpochs", nil)

	// serviceDesc is the gRCP service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetBaseEpoch.ShortName(),
				Handler:    handlerGetBaseEpoch,
			},
			{
				MethodName: methodGetEpoch.ShortName(),
				Handler:    handlerGetEpoch,
			},
			{
				MethodName: methodGetFutureEpoch.ShortName(),
				Handler:    handlerGetFutureEpoch,
			},
			{
				MethodName: methodWaitEpoch.ShortName(),
				Handler:    handlerWaitEpoch,
			},
			{
				MethodName: methodGetEpochBlock.ShortName(),
				Handler:    handlerGetEpochBlock,
			},
			{
				MethodName: methodGetBeacon.ShortName(),
				Handler:    handlerGetBeacon,
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
				MethodName: methodGetPVSSState.ShortName(),
				Handler:    handlerGetPVSSState,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchEpochs.ShortName(),
				Handler:       handlerWatchEpochs,
				ServerStreams: true,
			},
		},
	}
)

func handlerGetBaseEpoch( //nolint:golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(Backend).GetBaseEpoch(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBaseEpoch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetBaseEpoch(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetEpoch( //nolint:golint
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
		return srv.(Backend).GetEpoch(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEpoch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEpoch(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetFutureEpoch( //nolint:golint
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
		return srv.(Backend).GetFutureEpoch(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetFutureEpoch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetFutureEpoch(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerWaitEpoch( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var epoch EpochTime
	if err := dec(&epoch); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Backend).WaitEpoch(ctx, epoch)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodWaitEpoch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(Backend).WaitEpoch(ctx, req.(EpochTime))
	}
	return interceptor(ctx, epoch, info, handler)
}

func handlerGetEpochBlock( //nolint:golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var epoch EpochTime
	if err := dec(&epoch); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetEpochBlock(ctx, epoch)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEpochBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEpochBlock(ctx, req.(EpochTime))
	}
	return interceptor(ctx, epoch, info, handler)
}

func handlerGetBeacon( //nolint:golint
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
		return srv.(Backend).GetBeacon(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBeacon.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetBeacon(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
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

func handlerConsensusParameters( //nolint:golint
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

func handlerGetPVSSState( //nolint:golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	pvssBackend, ok := srv.(PVSSBackend)
	if !ok {
		return nil, fmt.Errorf("beacon: not using PVSS backend")
	}
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return pvssBackend.GetPVSSState(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetPVSSState.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return pvssBackend.GetPVSSState(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerWatchEpochs(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEpochs(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case epoch, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(epoch); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new beacon service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type beaconClient struct {
	conn *grpc.ClientConn
}

func (c *beaconClient) GetBaseEpoch(ctx context.Context) (EpochTime, error) {
	var rsp EpochTime
	if err := c.conn.Invoke(ctx, methodGetBaseEpoch.FullName(), nil, &rsp); err != nil {
		return 0, err
	}
	return rsp, nil
}

func (c *beaconClient) GetEpoch(ctx context.Context, height int64) (EpochTime, error) {
	var rsp EpochTime
	if err := c.conn.Invoke(ctx, methodGetEpoch.FullName(), height, &rsp); err != nil {
		return 0, err
	}
	return rsp, nil
}

func (c *beaconClient) GetFutureEpoch(ctx context.Context, height int64) (*EpochTimeState, error) {
	var rsp EpochTimeState
	if err := c.conn.Invoke(ctx, methodGetFutureEpoch.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *beaconClient) GetEpochBlock(ctx context.Context, epoch EpochTime) (int64, error) {
	var rsp int64
	if err := c.conn.Invoke(ctx, methodGetEpochBlock.FullName(), epoch, &rsp); err != nil {
		return 0, err
	}
	return rsp, nil
}

func (c *beaconClient) WaitEpoch(ctx context.Context, epoch EpochTime) error {
	return c.conn.Invoke(ctx, methodWaitEpoch.FullName(), epoch, nil)
}

func (c *beaconClient) WatchEpochs(ctx context.Context) (<-chan EpochTime, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEpochs.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan EpochTime)
	go func() {
		defer close(ch)

		for {
			var epoch EpochTime
			if serr := stream.RecvMsg(&epoch); serr != nil {
				return
			}

			select {
			case ch <- epoch:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *beaconClient) WatchLatestEpoch(ctx context.Context) (<-chan EpochTime, pubsub.ClosableSubscription, error) {
	// The only thing that uses this is the registration worker, and it
	// is not over gRPC.
	return nil, nil, fmt.Errorf("beacon: gRPC method not implemented")
}

func (c *beaconClient) GetBeacon(ctx context.Context, height int64) ([]byte, error) {
	var rsp []byte
	if err := c.conn.Invoke(ctx, methodGetBeacon.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *beaconClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *beaconClient) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var rsp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *beaconClient) GetPVSSState(ctx context.Context, height int64) (*PVSSState, error) {
	var rsp PVSSState
	if err := c.conn.Invoke(ctx, methodGetPVSSState.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *beaconClient) WatchLatestPVSSEvent(ctx context.Context) (<-chan *PVSSEvent, *pubsub.Subscription, error) {
	// The only thing that uses this is the beacon worker, and it is not
	// over gRPC.
	return nil, nil, fmt.Errorf("beacon: gRPC method not implemented")
}

func (c *beaconClient) Cleanup() {
}

// NewBeaconClient creates a new gRPC scheduler client service.
func NewBeaconClient(c *grpc.ClientConn) Backend {
	return &beaconClient{c}
}
