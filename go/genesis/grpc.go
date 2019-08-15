package genesis

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/json"
	genesis "github.com/oasislabs/ekiden/go/genesis/api"
	pb "github.com/oasislabs/ekiden/go/grpc/genesis"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	staking "github.com/oasislabs/ekiden/go/staking/api"
)

var (
	_ pb.GenesisServer = (*grpcServer)(nil)
)

type grpcServer struct {
	keymanagerBackend keymanager.Backend
	registryBackend   registry.Backend
	roothashBackend   roothash.Backend
	stakingBackend    staking.Backend
}

// ToGenesis generates a genesis document based on current state at given height.
func (s *grpcServer) ToGenesis(ctx context.Context, req *pb.GenesisRequest) (*pb.GenesisResponse, error) {
	height := req.GetHeight()

	// Call ToGenesis on all backends and merge the results together.
	registryGenesis, err := s.registryBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	roothashGenesis, err := s.roothashBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	stakingGenesis, err := s.stakingBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}
	keymanagerGenesis, err := s.keymanagerBackend.ToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	doc := genesis.Document{
		Time:       time.Now(),
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		KeyManager: *keymanagerGenesis,
	}

	// Return final genesis document as JSON.
	resp := pb.GenesisResponse{
		Json: json.Marshal(doc),
	}
	return &resp, nil
}

func NewGRPCServer(grpc *grpc.Server, km keymanager.Backend, reg registry.Backend, rh roothash.Backend, s staking.Backend) {
	srv := &grpcServer{
		keymanagerBackend: km,
		registryBackend:   reg,
		roothashBackend:   rh,
		stakingBackend:    s,
	}
	pb.RegisterGenesisServer(grpc, srv)
}
