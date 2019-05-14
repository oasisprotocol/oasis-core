package keymanager

import (
	"context"

	pb "github.com/oasislabs/ekiden/go/grpc/enclaverpc"
)

var _ pb.EnclaveRpcServer = (*grpcServer)(nil)

type grpcServer struct {
	w *worker
}

func (s *grpcServer) CallEnclave(ctx context.Context, req *pb.CallEnclaveRequest) (*pb.CallEnclaveResponse, error) {
	rsp, err := s.w.callLocal(ctx, req.Payload)
	if err != nil {
		return nil, err
	}

	return &pb.CallEnclaveResponse{Payload: rsp}, nil
}

func newEnclaveRPCGRPCServer(w *worker) {
	s := &grpcServer{w}
	pb.RegisterEnclaveRpcServer(w.grpc.Server(), s)
}
