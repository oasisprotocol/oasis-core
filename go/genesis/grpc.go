package genesis

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	pb "github.com/oasislabs/oasis-core/go/grpc/genesis"
)

var (
	_ pb.GenesisServer = (*grpcServer)(nil)
)

type grpcServer struct {
	logger *logging.Logger

	consensusBackend consensus.Backend
}

// ToGenesis generates a genesis document based on current state at given height.
func (s *grpcServer) ToGenesis(ctx context.Context, req *pb.GenesisRequest) (*pb.GenesisResponse, error) {
	height := req.GetHeight()

	// Get consensus state as a genesis doc.
	genesisDoc, err := s.consensusBackend.ToGenesis(ctx, height)
	if err != nil {
		s.logger.Error("failed to generate genesis document",
			"height", height,
			"err", err,
		)
		return nil, err
	}

	// Return the document as JSON.
	b, err := json.Marshal(genesisDoc)
	if err != nil {
		return nil, err
	}
	resp := pb.GenesisResponse{
		Json: b,
	}
	return &resp, nil
}

func NewGRPCServer(grpc *grpc.Server, cb consensus.Backend) {
	srv := &grpcServer{
		logger:           logging.GetLogger("genesis/grpc"),
		consensusBackend: cb,
	}
	pb.RegisterGenesisServer(grpc, srv)
}
