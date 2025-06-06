package secrets

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("KeyManager.Secrets")

	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodGetStatus is the GetStatus method.
	methodGetStatus = serviceName.NewMethod("GetStatus", registry.NamespaceQuery{})
	// methodGetStatuses is the GetStatuses method.
	methodGetStatuses = serviceName.NewMethod("GetStatuses", int64(0))
	// methodGetMasterSecret is the GetMasterSecret method.
	methodGetMasterSecret = serviceName.NewMethod("GetMasterSecret", registry.NamespaceQuery{})
	// methodGetEphemeralSecret is the GetEphemeralSecret method.
	methodGetEphemeralSecret = serviceName.NewMethod("GetEphemeralSecret", registry.NamespaceQuery{})

	// methodWatchStatuses is the WatchStatuses method.
	methodWatchStatuses = serviceName.NewMethod("WatchStatuses", nil)
	// methodWatchMasterSecrets is the WatchMasterSecrets method.
	methodWatchMasterSecrets = serviceName.NewMethod("WatchMasterSecrets", nil)
	// methodWatchEphemeralSecrets is the WatchEphemeralSecrets method.
	methodWatchEphemeralSecrets = serviceName.NewMethod("WatchEphemeralSecrets", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodGetStatus.ShortName(),
				Handler:    handlerGetStatus,
			},
			{
				MethodName: methodGetStatuses.ShortName(),
				Handler:    handlerGetStatuses,
			},
			{
				MethodName: methodGetMasterSecret.ShortName(),
				Handler:    handlerGetMasterSecret,
			},
			{
				MethodName: methodGetEphemeralSecret.ShortName(),
				Handler:    handlerGetEphemeralSecret,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchStatuses.ShortName(),
				Handler:       handlerWatchStatuses,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchMasterSecrets.ShortName(),
				Handler:       handlerWatchMasterSecrets,
				ServerStreams: true,
			},
			{
				StreamName:    methodWatchEphemeralSecrets.ShortName(),
				Handler:       handlerWatchEphemeralSecrets,
				ServerStreams: true,
			},
		},
	}
)

func handlerStateToGenesis(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
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
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetStatus(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var query registry.NamespaceQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetStatus(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatus.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Backend).GetStatus(ctx, req.(*registry.NamespaceQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetStatuses(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetStatuses(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatuses.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Backend).GetStatuses(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetMasterSecret(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var query registry.NamespaceQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetMasterSecret(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetMasterSecret.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Backend).GetMasterSecret(ctx, req.(*registry.NamespaceQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerGetEphemeralSecret(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var query registry.NamespaceQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetEphemeralSecret(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEphemeralSecret.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Backend).GetEphemeralSecret(ctx, req.(*registry.NamespaceQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerWatchStatuses(srv any, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchStatuses(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case stat, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(stat); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchMasterSecrets(srv any, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchMasterSecrets(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case sec, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(sec); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerWatchEphemeralSecrets(srv any, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEphemeralSecrets(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case sec, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(sec); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new keymanager secrets backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

// Client is a gRPC key manager secrets client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC key manager secrets client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{c}
}

func (c *Client) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var resp *Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetStatus(ctx context.Context, query *registry.NamespaceQuery) (*Status, error) {
	var resp Status
	if err := c.conn.Invoke(ctx, methodGetStatus.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetStatuses(ctx context.Context, height int64) ([]*Status, error) {
	var resp []*Status
	if err := c.conn.Invoke(ctx, methodGetStatuses.FullName(), height, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetMasterSecret(ctx context.Context, query *registry.NamespaceQuery) (*SignedEncryptedMasterSecret, error) {
	var resp *SignedEncryptedMasterSecret
	if err := c.conn.Invoke(ctx, methodGetMasterSecret.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) GetEphemeralSecret(ctx context.Context, query *registry.NamespaceQuery) (*SignedEncryptedEphemeralSecret, error) {
	var resp *SignedEncryptedEphemeralSecret
	if err := c.conn.Invoke(ctx, methodGetEphemeralSecret.FullName(), query, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) WatchStatuses(ctx context.Context) (<-chan *Status, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchStatuses.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Status)
	go func() {
		defer close(ch)

		for {
			var stat Status
			if serr := stream.RecvMsg(&stat); serr != nil {
				return
			}

			select {
			case ch <- &stat:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *Client) WatchMasterSecrets(ctx context.Context) (<-chan *SignedEncryptedMasterSecret, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchMasterSecrets.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *SignedEncryptedMasterSecret)
	go func() {
		defer close(ch)

		for {
			var sec SignedEncryptedMasterSecret
			if serr := stream.RecvMsg(&sec); serr != nil {
				return
			}

			select {
			case ch <- &sec:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *Client) WatchEphemeralSecrets(ctx context.Context) (<-chan *SignedEncryptedEphemeralSecret, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEphemeralSecrets.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *SignedEncryptedEphemeralSecret)
	go func() {
		defer close(ch)

		for {
			var sec SignedEncryptedEphemeralSecret
			if serr := stream.RecvMsg(&sec); serr != nil {
				return
			}

			select {
			case ch <- &sec:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}
