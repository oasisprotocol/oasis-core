package keymanager

import (
	"context"

	pb "github.com/oasislabs/oasis-core/go/grpc/enclaverpc"
)

var _ pb.EnclaveRpcServer = (*grpcServer)(nil)

type grpcServer struct {
	w *Worker
}

func (s *grpcServer) CallEnclave(ctx context.Context, req *pb.CallEnclaveRequest) (*pb.CallEnclaveResponse, error) {
	rsp, err := s.w.callLocal(ctx, req.Payload)
	if err != nil {
		return nil, err
	}

	return &pb.CallEnclaveResponse{Payload: rsp}, nil
}

func newEnclaveRPCGRPCServer(w *Worker) {
	s := &grpcServer{w}
	pb.RegisterEnclaveRpcServer(w.commonWorker.Grpc.Server(), s)
}
