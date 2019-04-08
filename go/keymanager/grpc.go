package keymanager

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/oasislabs/ekiden/go/grpc/enclaverpc"
)

var _ pb.EnclaveRpcServer = (*grpcServer)(nil)

type grpcServer struct {
	km *KeyManager
}

func (s *grpcServer) CallEnclave(ctx context.Context, req *pb.CallEnclaveRequest) (*pb.CallEnclaveResponse, error) {
	rsp, err := s.km.callLocal(ctx, req.Payload)
	if err != nil {
		return nil, err
	}

	return &pb.CallEnclaveResponse{Payload: rsp}, nil
}

func newEnclaveRPCGRPCServer(srv *grpc.Server, km *KeyManager) {
	s := &grpcServer{km}
	pb.RegisterEnclaveRpcServer(srv, s)
}
