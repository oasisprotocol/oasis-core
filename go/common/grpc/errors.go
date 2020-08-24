package grpc

import (
	"context"

	any "github.com/golang/protobuf/ptypes/any"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
)

// IsErrorCode returns true if the given error represents a specific gRPC error code.
func IsErrorCode(err error, code codes.Code) bool {
	var grpcError interface {
		error
		GRPCStatus() *status.Status
	}
	if !errors.As(err, &grpcError) {
		return false
	}

	return grpcError.GRPCStatus().Code() == code
}

// grpcError is a serializable error.
type grpcError struct {
	Module string `json:"module,omitempty"`
	Code   uint32 `json:"code,omitempty"`
}

func errorToGrpc(err error) error {
	if err == nil {
		return nil
	}

	// Convert the error.
	module, code := errors.Code(err)
	if module == errors.UnknownModule {
		// If the error is not known, just pass the original error.
		return err
	}

	// NOTE: Although this is protobuf, the message is actually serialized using
	//       our provided CBOR codec when configured. We need to use this directly
	//       in order to be able to set the Details field.
	return status.FromProto(&spb.Status{
		// We keep any set gRPC error code (with fallback to codes.Unknown).
		Code:    int32(status.Code(err)),
		Message: err.Error(),
		Details: []*any.Any{
			{
				// Double serialization seems ugly, but there is no way around
				// it as the format for errors is predefined.
				Value: cbor.Marshal(&grpcError{Module: module, Code: code}),
			},
		},
	}).Err()
}

func errorFromGrpc(err error) error {
	if err == nil {
		return nil
	}

	// Convert the error back.
	if s, ok := status.FromError(err); ok {
		sp := s.Proto()
		if len(sp.Details) != 1 {
			return err
		}
		var ge grpcError
		if cerr := cbor.Unmarshal(sp.Details[0].Value, &ge); cerr != nil {
			return err
		}

		if mappedErr := errors.FromCode(ge.Module, ge.Code); mappedErr != nil {
			return mappedErr
		}
	}

	return err
}

func serverUnaryErrorMapper(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	rsp, err := handler(ctx, req)
	return rsp, errorToGrpc(err)
}

func serverStreamErrorMapper(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	err := handler(srv, ss)
	return errorToGrpc(err)
}

func clientUnaryErrorMapper(
	ctx context.Context,
	method string,
	req, rsp interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	err := invoker(ctx, method, req, rsp, cc, opts...)
	return errorFromGrpc(err)
}

func clientStreamErrorMapper(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	cs, err := streamer(ctx, desc, cc, method, opts...)
	return cs, errorFromGrpc(err)
}
