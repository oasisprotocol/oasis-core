package consensus

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	pb "github.com/oasislabs/oasis-core/go/grpc/consensus"
)

var _ pb.ConsensusServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) SubmitTx(ctx context.Context, req *pb.SubmitTxRequest) (*pb.SubmitTxResponse, error) {
	var tx transaction.SignedTransaction
	if err := cbor.Unmarshal(req.GetTx(), &tx); err != nil {
		return nil, fmt.Errorf("consensus: malformed signed transaction: %w", err)
	}

	if err := s.backend.SubmitTx(ctx, &tx); err != nil {
		return nil, err
	}
	return &pb.SubmitTxResponse{}, nil
}

func NewGRPCServer(grpc *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterConsensusServer(grpc, s)
}
