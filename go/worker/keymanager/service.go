package keymanager

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	"github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

var _ api.Transport = (*Worker)(nil)

// CallEnclave sends the request bytes to the target enclave.
func (w *Worker) CallEnclave(ctx context.Context, request *api.CallEnclaveRequest) ([]byte, error) {
	if mustAllow := w.mustAllowAccess(ctx, request.Payload); !mustAllow {
		// TODO: In the future we should be using the namespace type for runtime IDs.
		var ns common.Namespace
		copy(ns[:], request.RuntimeID[:])

		if err := w.grpcPolicy.CheckAccessAllowed(ctx, accessctl.Action("CallEnclave"), ns); err != nil {
			return nil, err
		}
	}

	if request.Endpoint != keymanager.EnclaveRPCEndpoint {
		return nil, fmt.Errorf("unsupported endpoint: %s", request.Endpoint)
	}

	return w.callLocal(ctx, request.Payload)
}
