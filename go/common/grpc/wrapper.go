package grpc

import (
	"context"
	"errors"
	"strings"
	"sync"

	"google.golang.org/grpc"
)

// ErrServiceClosed is the error returned when the wrapper receives a message for a service whose
// interceptor has been removed.
var ErrServiceClosed = errors.New("grpc/wrapper: received message for wrapped service with deregistered wrapper")

type wrappedResponse struct {
	resp interface{}
	err  error
}

// WrappedRequestCommon is a struct with common metadata about intercepted GRPC requests.
type WrappedRequestCommon struct {
	Method string
}

// WrappedUnaryRequest is an unary GRPC request packet.
type WrappedUnaryRequest struct {
	WrappedRequestCommon

	Context context.Context
	Request interface{}
	Info    *grpc.UnaryServerInfo
	Handler grpc.UnaryHandler
}

// Forward forwards the wrapped request further down the GRPC stack, potentially to the original server implementation.
func (u *WrappedUnaryRequest) Forward() (interface{}, error) {
	return u.Handler(u.Context, u.Request)
}

// WrappedStreamRequest is a stream GRPC request packet.
type WrappedStreamRequest struct {
	WrappedRequestCommon

	Server  interface{}
	Stream  grpc.ServerStream
	Info    *grpc.StreamServerInfo
	Handler grpc.StreamHandler
}

// Forward forwards the wrapped request further down the GRPC stack, potentially to the original server implementation.
func (s *WrappedStreamRequest) Forward() error {
	return s.Handler(s.Server, s.Stream)
}

// WrappedRequest is a struct containing either a wrapped unary or stream request.
type WrappedRequest struct {
	// Unary is a wrapped unary request.
	Unary *WrappedUnaryRequest
	// Stream is a wrapped stream request.
	Stream *WrappedStreamRequest

	returnCh chan *wrappedResponse
}

// Respond sends the given response back to the GRPC wrapper.
func (req *WrappedRequest) Respond(resp interface{}, err error) {
	req.returnCh <- &wrappedResponse{
		resp: resp,
		err:  err,
	}
}

// Forward forwards the request to the original handler and returns its return values.
func (req *WrappedRequest) Forward() (interface{}, error) {
	if req.Unary != nil {
		return req.Unary.Forward()
	}
	return nil, req.Stream.Forward()
}

type wrapperSpec struct {
	prefix string
	reqCh  chan<- *WrappedRequest
}

var nilWrapper = &wrapperSpec{}

type grpcWrapper struct {
	sync.RWMutex

	wrappers map[string]*wrapperSpec
}

func (w *grpcWrapper) getApplicable(fullMethod string) *wrapperSpec {
	w.RLock()
	defer w.RUnlock()

	for prefix, spec := range w.wrappers {
		if strings.HasPrefix(fullMethod, prefix) {
			return spec
		}
	}
	return nil
}

func (w *grpcWrapper) unaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	wrapper := w.getApplicable(info.FullMethod)
	if wrapper != nil {
		if wrapper == nilWrapper {
			return nil, ErrServiceClosed
		}

		packet := &WrappedRequest{
			Unary: &WrappedUnaryRequest{
				WrappedRequestCommon: WrappedRequestCommon{
					Method: info.FullMethod,
				},

				Context: ctx,
				Request: req,
				Info:    info,
				Handler: handler,
			},
			returnCh: make(chan *wrappedResponse),
		}
		defer close(packet.returnCh)

		wrapper.reqCh <- packet
		resp := <-packet.returnCh
		return resp.resp, resp.err
	}
	return handler(ctx, req)
}

func (w *grpcWrapper) streamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	wrapper := w.getApplicable(info.FullMethod)
	if wrapper != nil {
		if wrapper == nilWrapper {
			return ErrServiceClosed
		}

		packet := &WrappedRequest{
			Stream: &WrappedStreamRequest{
				WrappedRequestCommon: WrappedRequestCommon{
					Method: info.FullMethod,
				},

				Server:  srv,
				Stream:  ss,
				Info:    info,
				Handler: handler,
			},
			returnCh: make(chan *wrappedResponse),
		}
		defer close(packet.returnCh)

		wrapper.reqCh <- packet
		resp := <-packet.returnCh
		return resp.err
	}
	return handler(srv, ss)
}

func newWrapper() *grpcWrapper {
	return &grpcWrapper{
		wrappers: make(map[string]*wrapperSpec),
	}
}

// RegisterServiceWrapper registers a wrapper for the specified GRPC service and registers it with the GRPC server.
//
// Note: In case multiple wrappers are registered with the same prefix, only the first one will be used.
// If a wrapper is registered with a prefix that overlaps with the same set of services as another prefix,
// then both such wrappers will be called, potentially confusing the remote end of the connection.
func (s *Server) RegisterServiceWrapper(prefix string, registrator func(*grpc.Server)) <-chan *WrappedRequest {
	if s.wrapper == nil {
		panic("grpc/wrapper: attempted to install service wrapper on server without interceptor")
	}

	s.wrapper.Lock()
	defer s.wrapper.Unlock()

	if _, ok := s.wrapper.wrappers[prefix]; ok {
		panic("grpc/wrapper: service wrapper already registered")
	}

	channel := make(chan *WrappedRequest)

	s.wrapper.wrappers[prefix] = &wrapperSpec{
		prefix: prefix,
		reqCh:  channel,
	}

	registrator(s.Server())

	return channel
}

// DeregisterServiceWrapper removes the specified service wrapper from the stack. Subsequent messages the service
// might receive will be answered with an error response.
func (s *Server) DeregisterServiceWrapper(prefix string) {
	if s.wrapper == nil {
		panic("grpc/wrapper: attempted to remove service wrapper from server without interceptor")
	}

	s.wrapper.Lock()
	defer s.wrapper.Unlock()

	if spec, ok := s.wrapper.wrappers[prefix]; ok {
		close(spec.reqCh)
		delete(s.wrapper.wrappers, prefix)

		// No way to unregister a service from the server. Prevent crashes by gobbling requests.
		s.wrapper.wrappers[prefix] = nilWrapper
	}
}
