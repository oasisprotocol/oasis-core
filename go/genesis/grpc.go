package genesis

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus"
	pb "github.com/oasislabs/oasis-core/go/grpc/genesis"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	_ pb.GenesisServer = (*grpcServer)(nil)
)

type grpcServer struct {
	logger *logging.Logger

	consensusBackend consensus.Backend

	keymanagerBackend keymanager.Backend
	registryBackend   registry.Backend
	roothashBackend   roothash.Backend
	stakingBackend    staking.Backend
	schedulerBackend  scheduler.Backend
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

func NewGRPCServer(grpc *grpc.Server, cb consensus.Backend, km keymanager.Backend, reg registry.Backend, rh roothash.Backend, s staking.Backend, sch scheduler.Backend) {
	srv := &grpcServer{
		logger:            logging.GetLogger("genesis/grpc"),
		consensusBackend:  cb,
		keymanagerBackend: km,
		registryBackend:   reg,
		roothashBackend:   rh,
		stakingBackend:    s,
		schedulerBackend:  sch,
	}
	pb.RegisterGenesisServer(grpc, srv)
}
