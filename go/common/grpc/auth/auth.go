// Package auth implements gRPC authentication server interceptors.
package auth

import (
	"context"

	"google.golang.org/grpc"
)

// AuthenticationFunction defines the gRPC server default authentication function. This
// can be overridden per service by implementing AuthFunc on the gRPC service.
type AuthenticationFunction func(ctx context.Context, fullMethodName string, req interface{}) error

// NoAuth is a function that does no authentication.
func NoAuth(ctx context.Context, fullMethodName string, req interface{}) error {
	return nil
}

// ServerAuth interface defines gRPC server authentication interface.
type ServerAuth interface {
	// AuthFunc is the authentication function. The authentication can be done
	// on the method name, metadata (can be obtained from ctx) and incoming
	// request.
	//
	// Make sure to error with `codes.Unauthenticated` and
	// `codes.PermissionDenied` appropriately.
	AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error
}

// UnaryServerInterceptor returns an authentication unary server interceptor.
func UnaryServerInterceptor(authFunc AuthenticationFunction) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {
		overrideSrv, ok := info.Server.(ServerAuth)
		if !ok {
			// Server doesn't implement Authentication.
			// Use default Auth.
			if err := authFunc(ctx, info.FullMethod, req); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}

		if err := overrideSrv.AuthFunc(ctx, info.FullMethod, req); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns an authentication stream server interceptor.
//
// StreamServerInterceptor wraps the incoming server stream and authenticates
// all received messages.
func StreamServerInterceptor(authFunc AuthenticationFunction) grpc.StreamServerInterceptor {
	return func(srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {
		overrideSrv, ok := srv.(ServerAuth)
		if !ok {
			// Server doesn't implement Authentication.
			// Use default Auth.
			return handler(srv, &authServerStream{
				ServerStream: stream,
				fullMethod:   info.FullMethod,
				authFunc:     authFunc,
			})
		}

		return handler(srv, &authServerStream{
			ServerStream: stream,
			fullMethod:   info.FullMethod,
			authFunc:     overrideSrv.AuthFunc,
		})
	}
}

var _ grpc.ServerStream = (*authServerStream)(nil)

// authServerStream wraps the incoming server stream and authenticates all
// received messages.
type authServerStream struct {
	grpc.ServerStream

	fullMethod string
	authFunc   func(ctx context.Context, fullMethodName string, req interface{}) error
}

func (a authServerStream) RecvMsg(m interface{}) error {
	if err := a.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	// Authenticate request.
	return a.authFunc(a.Context(), a.fullMethod, m)
}
