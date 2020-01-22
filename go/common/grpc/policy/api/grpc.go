package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("PolicyWatcher")

	// methodWatchPolicies is the WatchPolicies method.
	methodWatchPolicies = serviceName.NewMethod("WatchPolicies", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*PolicyWatcher)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchPolicies.ShortName(),
				Handler:       handlerWatchPolicies,
				ServerStreams: true,
			},
		},
	}
)

func handlerWatchPolicies(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(PolicyWatcherClient).WatchPolicies(ctx)
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

// RegisterService registers a new policy watcher service with the given gRPC server.
func RegisterService(server *grpc.Server, service PolicyWatcher) {
	server.RegisterService(&serviceDesc, service)
}

type policyWatcherClient struct {
	conn *grpc.ClientConn
}

func (c *policyWatcherClient) WatchPolicies(ctx context.Context) (<-chan ServicePolicies, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchPolicies.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan ServicePolicies)
	go func() {
		defer close(ch)

		for {
			var ev ServicePolicies
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

// NewPolicyWatcherClient creates a new gRPC policy watcher
// client service.
func NewPolicyWatcherClient(c *grpc.ClientConn) PolicyWatcherClient {
	return &policyWatcherClient{c}
}
