// Package proxy implements service agnostic gRPC reverse proxy.
//
// This package is somewhat inspired by https://github.com/mwitkow/grpc-proxy.
package proxy

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	policy "github.com/oasisprotocol/oasis-core/go/common/grpc/policy/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

// Dialer should return a gRPC ClientConn that will be used
// to forward calls to.
type Dialer func(ctx context.Context) (*grpc.ClientConn, error)

// Handler returns a gRPC StreamHandler than can be used
// to proxy requests to the client returned by the proxy dialer.
func Handler(dialer Dialer) grpc.StreamHandler {
	proxy := &proxy{
		logger:       logging.GetLogger("grpc/proxy"),
		dialer:       dialer,
		upstreamConn: nil, // Will be dialed on-demand.
	}

	return grpc.StreamHandler(proxy.handler)
}

type proxy struct {
	// This is the dialer callback we use to make new connections to the
	// upstream server if the connection drops, etc.
	dialer Dialer

	// This is a cached client connection to the upstream server, so we
	// don't have to re-dial it on every call.
	upstreamConn *grpc.ClientConn

	logger *logging.Logger

	// XXX: Currently for each incoming stream two goroutines are spawned,
	// could instead use a pool of worker routines (e.g. common/workerpool).
}

func (p *proxy) handler(srv interface{}, stream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		p.logger.Error("missing method in client request")
		return status.Errorf(codes.Internal, "missing method in client request")
	}

	// Upstream stream.
	upstreamCtx, upstreamCancel := context.WithCancel(stream.Context())
	defer upstreamCancel()
	desc := &grpc.StreamDesc{
		ServerStreams: true,
		ClientStreams: true,
	}
	sub, err := policy.SubjectFromGRPCContext(upstreamCtx)
	if err != nil {
		// Connections without TLS client authentication are allowed as there may be methods which
		// do not require access control. We still need to pass an (empty) forwarded subject as
		// otherwise the connection may be treated as not forwarded through the proxy.
		sub = ""

		p.logger.Debug("failed extracting peer from context (unauthenticated connection)",
			"err", err,
		)
	}

	// Pass subject header upstream.
	upstreamCtx = metadata.AppendToOutgoingContext(upstreamCtx, policy.ForwardedSubjectMD, sub)

	// Check if upstream connection was disconnected.
	if p.upstreamConn != nil && p.upstreamConn.GetState() == connectivity.Shutdown {
		// We need to redial if the connection was shut down.
		p.upstreamConn = nil
	}

	// Dial upstream if necessary.
	if p.upstreamConn == nil {
		var grr error
		p.upstreamConn, grr = p.dialer(stream.Context())
		if grr != nil {
			return grr
		}
	}

	upstreamStream, err := grpc.NewClientStream(
		upstreamCtx,
		desc,
		p.upstreamConn,
		method,
	)
	if err != nil {
		return err
	}

	// Proxy upstream.
	upErrCh := p.proxyUpstream(stream, upstreamStream)

	// Proxy downstream.
	downErrCh := p.proxyDownstream(upstreamStream, stream)

	// Wait for errors.
	for {
		select {
		case err := <-upErrCh:
			if err == io.EOF {
				// Received EOF from downstream client, the server response
				// can still be in progress.
				p.logger.Debug("downstream EOF")
				if err = upstreamStream.CloseSend(); err != nil {
					p.logger.Error("failure closing upstream stream",
						"err", err,
					)
				}
			} else {
				return err
			}
			break
		case err := <-downErrCh:
			// Received Error from upstream server.
			// Proxy trailer if remains and propagate the error.
			stream.SetTrailer(upstreamStream.Trailer())
			if err == io.EOF {
				p.logger.Debug("upstream EOF")
				return nil
			}
			return err
		}
	}
}

// Client -> Upstream
func (p *proxy) proxyUpstream(downstream grpc.ServerStream, upstream grpc.ClientStream) <-chan error {
	errCh := make(chan error, 1)

	go func() {
		for {
			// XXX: since we are using CBOR we are able to unmarshal messages
			// without knowing the schema. This wouldn't work with protobuf, and
			// a raw binary codec would have to be used.
			var m cbor.RawMessage
			if err := downstream.RecvMsg(&m); err != nil {
				if err != io.EOF {
					p.logger.Error("failure receiving msg from client",
						"err", err,
					)
				}
				errCh <- err
				return
			}

			p.logger.Debug("received msg from downstream",
				"msg", m,
			)

			if err := upstream.SendMsg(m); err != nil {
				p.logger.Error("failure forwarding message upstream",
					"err", err,
				)
				errCh <- err
				return
			}
		}
	}()

	return errCh
}

// Upstream -> Client
func (p *proxy) proxyDownstream(upstream grpc.ClientStream, downstream grpc.ServerStream) <-chan error {
	errCh := make(chan error, 1)
	var headerSent bool

	go func() {
		for {
			// Wait for stream msg (from upstream).
			// XXX: since we are using CBOR we are able to unmarshal messages
			// without knowing the schema. This wouldn't work with protobuf, and
			// a raw binary codec would have to be used.
			var m cbor.RawMessage
			if err := upstream.RecvMsg(&m); err != nil {
				if err != io.EOF {
					p.logger.Error("failure receiving msg from upstream",
						"err", err,
					)
				}
				errCh <- err
				return
			}

			// Header is only available after the first message is received.
			if !headerSent {
				// Forward header downstream.
				h, err := upstream.Header()
				if err != nil {
					p.logger.Error("failure extracting server header",
						"err", err,
					)
					errCh <- err
					return
				}
				if err := downstream.SendHeader(h); err != nil {
					p.logger.Error("failure forwarding header downstream",
						"err", err,
					)
					errCh <- err
					return
				}
				headerSent = true
			}

			// Forward msg downstream.
			if err := downstream.SendMsg(m); err != nil {
				p.logger.Error("failure forwarding msg upstream",
					"err", err,
				)
				errCh <- err
				return
			}
		}
	}()

	return errCh
}
