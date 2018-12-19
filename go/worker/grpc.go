package worker

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/committee"
	"github.com/oasislabs/ekiden/go/worker/committee"
)

var _ pb.RuntimeServer = (*grpcServer)(nil)

type grpcServer struct {
	worker *Worker
}

func (s *grpcServer) SubmitTx(ctx context.Context, req *pb.SubmitTxRequest) (*pb.SubmitTxResponse, error) {
	var runtimeID signature.MapKey
	if len(req.GetRuntimeId()) != signature.PublicKeySize {
		return nil, errors.New("invalid runtime identifier")
	}
	copy(runtimeID[:], req.GetRuntimeId())

	runtime, ok := s.worker.runtimes[runtimeID]
	if !ok {
		return nil, errors.New("unknown runtime")
	}

	if err := runtime.node.QueueCall(ctx, req.GetData()); err != nil {
		if err == committee.ErrNotLeader {
			return nil, status.Error(codes.Unavailable, err.Error())
		}

		return nil, err
	}

	return &pb.SubmitTxResponse{}, nil
}

func newClientGRPCServer(srv *grpc.Server, worker *Worker) {
	s := &grpcServer{worker}
	pb.RegisterRuntimeServer(srv, s)
}
