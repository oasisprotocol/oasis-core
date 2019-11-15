package txnscheduler

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	pb "github.com/oasislabs/oasis-core/go/grpc/txnscheduler"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/committee"
)

var _ pb.TransactionSchedulerServer = (*grpcServer)(nil)

type grpcServer struct {
	worker *Worker
}

func (s *grpcServer) SubmitTx(ctx context.Context, req *pb.SubmitTxRequest) (*pb.SubmitTxResponse, error) {
	var runtimeID signature.PublicKey
	if err := runtimeID.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

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

func (s *grpcServer) IsTransactionQueued(ctx context.Context, req *pb.IsTransactionQueuedRequest) (*pb.IsTransactionQueuedResponse, error) {
	var runtimeID signature.PublicKey
	if err := runtimeID.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	var id hash.Hash
	if err := id.UnmarshalBinary(req.GetHash()); err != nil {
		return nil, err
	}

	runtime, ok := s.worker.runtimes[runtimeID]
	if !ok {
		return nil, errors.New("unknown runtime")
	}

	isQueued, err := runtime.node.IsTransactionQueued(ctx, id)
	if err != nil {
		if err == committee.ErrNotLeader {
			return nil, status.Error(codes.Unavailable, err.Error())
		}

		return nil, err
	}

	return &pb.IsTransactionQueuedResponse{
		IsQueued: isQueued,
	}, nil
}

func newClientGRPCServer(srv *grpc.Server, worker *Worker) {
	s := &grpcServer{worker}
	pb.RegisterTransactionSchedulerServer(srv, s)
}
