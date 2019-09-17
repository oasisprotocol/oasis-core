package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/grpc"

	pb "github.com/oasislabs/oasis-core/go/grpc/enclaverpc"
)

var _ pb.EnclaveRpcServer = (*grpcServer)(nil)

type grpcServer struct {
	grpc.RuntimePolicyChecker

	w *Worker
}

func (s *grpcServer) CallEnclave(ctx context.Context, req *pb.CallEnclaveRequest) (*pb.CallEnclaveResponse, error) {
	if mustAllow := s.w.mustAllowAccess(ctx, req.Payload); !mustAllow {
		var ns common.Namespace
		copy(ns[:], s.w.runtimeID)

		if err := s.CheckAccessAllowed(ctx, accessctl.Action("CallEnclave"), ns); err != nil {
			return nil, err
		}
	}

	rsp, err := s.w.callLocal(ctx, req.Payload)
	if err != nil {
		return nil, err
	}

	return &pb.CallEnclaveResponse{Payload: rsp}, nil
}

func newEnclaveRPCGRPCServer(w *Worker) {
	s := &grpcServer{RuntimePolicyChecker: w.grpcPolicy, w: w}
	pb.RegisterEnclaveRpcServer(w.commonWorker.Grpc.Server(), s)
}
