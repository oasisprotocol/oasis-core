// Package testing implements common grpc testing helpers.
package testing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

var (
	errInvalidRequestType = fmt.Errorf("invalid request type")

	_ PingServer      = (*pingServer)(nil)
	_ auth.ServerAuth = (*pingServer)(nil)
	_ PingClient      = (*pingClient)(nil)

	// Register Ping gRPC Service.
	serviceName = cmnGrpc.NewServiceName("PingService")
	// MethodPing is the Ping method.
	MethodPing = serviceName.NewMethod("Ping", PingQuery{}).
			WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*PingQuery)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
		return true, nil
	})

	// MethodWatchPings is the WatchPings method.
	MethodWatchPings = serviceName.NewMethod("WatchPings", PingQuery{}).
				WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*PingQuery)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
		return true, nil
	})
)

// CreateCertificate creates gRPC TLS certificate for testing.
func CreateCertificate(t *testing.T) (*tls.Certificate, *x509.Certificate) {
	require := require.New(t)

	dataDir, err := ioutil.TempDir("", "oasis-common-grpc-test_")
	require.NoError(err, "Failed to create a temporary directory")
	defer os.RemoveAll(dataDir)

	ident, err := identity.LoadOrGenerate(dataDir, memorySigner.NewFactory(), false)
	require.NoError(err, "Failed to generate a new identity")
	require.Len(ident.GetTLSCertificate().Certificate, 1, "The generated identity contains more than 1 TLS certificate in the chain")

	x509Cert, err := x509.ParseCertificate(ident.GetTLSCertificate().Certificate[0])
	require.NoError(err, "Failed to parse X.509 certificate from TLS certificate")

	return ident.GetTLSCertificate(), x509Cert
}

// PingQuery is the PingServer query.
type PingQuery struct {
	common.Namespace
}

// PingResponse is the response of the PingServer.
type PingResponse struct{}

// PingServer is a testing ping server interface.
type PingServer interface {
	Ping(context.Context, *PingQuery) (*PingResponse, error)
	WatchPings(context.Context, *PingQuery) (<-chan *PingResponse, pubsub.ClosableSubscription, error)
}

type pingServer struct {
	authFunc func(ctx context.Context, fullMethodName string, req interface{}) error
}

func (s *pingServer) AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error {
	return s.authFunc(ctx, fullMethodName, req)
}

func (s *pingServer) Ping(ctx context.Context, query *PingQuery) (*PingResponse, error) {
	return &PingResponse{}, nil
}

func (s *pingServer) WatchPings(ctx context.Context, query *PingQuery) (<-chan *PingResponse, pubsub.ClosableSubscription, error) {
	pingNotifier := pubsub.NewBroker(true)
	go func() {
		for {
			select {
			case <-time.After(100 * time.Millisecond):
				pingNotifier.Broadcast(&PingResponse{})
			case <-ctx.Done():
				return
			}
		}
	}()
	typedCh := make(chan *PingResponse)
	sub := pingNotifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

// RegisterService registers a new ping server service with the given gRPC server.
func RegisterService(server *grpc.Server, service PingServer) {
	server.RegisterService(&ServiceDesc, service)
}

// NewPingServer retruns a new Ping server.
func NewPingServer(authFunc func(ctx context.Context, fullMethodName string, req interface{}) error) PingServer {
	ps := &pingServer{authFunc}
	return ps
}

// NewPingClient returns a new ping client.
func NewPingClient(conn *grpc.ClientConn) PingClient {
	return &pingClient{conn}
}

// PingClient is a testing PingServer client.
type PingClient interface {
	Ping(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (*PingResponse, error)
	WatchPings(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (<-chan *PingResponse, pubsub.ClosableSubscription, error)
	MissingMethod(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (*PingResponse, error)
}

type pingClient struct {
	cc *grpc.ClientConn
}

func (c *pingClient) Ping(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (*PingResponse, error) {
	out := new(PingResponse)
	err := c.cc.Invoke(ctx, MethodPing.FullName(), in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pingClient) WatchPings(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (<-chan *PingResponse, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.cc.NewStream(ctx, &ServiceDesc.Streams[0], MethodWatchPings.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *PingResponse)
	go func() {
		defer close(ch)

		for {
			var pr PingResponse
			if serr := stream.RecvMsg(&pr); serr != nil {
				return
			}

			select {
			case ch <- &pr:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *pingClient) MissingMethod(ctx context.Context, in *PingQuery, opts ...grpc.CallOption) (*PingResponse, error) {
	out := new(PingResponse)
	err := c.cc.Invoke(ctx, "/PingService/PingMissing", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServiceDesc is the PingService gRPC description.
var ServiceDesc = grpc.ServiceDesc{
	ServiceName: string(serviceName),
	HandlerType: (*PingServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: MethodPing.ShortName(),
			Handler:    pingHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    MethodWatchPings.ShortName(),
			Handler:       watchPingsHandler,
			ServerStreams: true,
		},
	},
}

func pingHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	pq := new(PingQuery)
	if err := dec(pq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PingServer).Ping(ctx, pq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodPing.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PingServer).Ping(ctx, req.(*PingQuery))
	}
	return interceptor(ctx, pq, info, handler)
}

func watchPingsHandler(srv interface{}, stream grpc.ServerStream) error {
	pq := new(PingQuery)
	if err := stream.RecvMsg(pq); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(PingServer).WatchPings(ctx, pq)
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
