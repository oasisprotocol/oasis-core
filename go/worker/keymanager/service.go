package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/grpc/auth"
	"github.com/oasislabs/oasis-core/go/common/grpc/policy"
	"github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

var (
	_ api.Transport   = (*Worker)(nil)
	_ auth.ServerAuth = (*Worker)(nil)
)

// AuthFunc is the gRPC service authentication function.
func (w *Worker) AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error {
	return policy.GRPCAuthenticationFunction(w.grpcPolicy)(ctx, fullMethodName, req)
}

// CallEnclave sends the request bytes to the target enclave.
func (w *Worker) CallEnclave(ctx context.Context, request *api.CallEnclaveRequest) ([]byte, error) {
	return w.callLocal(ctx, request.Payload)
}
