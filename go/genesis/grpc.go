package genesis

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/genesis/api"
	pb "github.com/oasislabs/ekiden/go/grpc/genesis"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var (
	_ pb.GenesisServer = (*grpcServer)(nil)
)

type grpcServer struct {
	tendermintService service.TendermintService

	keymanagerBackend keymanager.Backend
	registryBackend   registry.Backend
	roothashBackend   roothash.Backend
	stakingBackend    staking.Backend
}

// ToGenesis generates a genesis document based on current state at given height.
func (s *grpcServer) ToGenesis(ctx context.Context, req *pb.GenesisRequest) (*pb.GenesisResponse, error) {
	height := req.GetHeight()
	if height <= 0 {
		var err error
		if height, err = s.tendermintService.GetHeight(); err != nil {
			return nil, err
		}
	}

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

	doc := api.Document{
		Height:     0,
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

func NewGRPCServer(grpc *grpc.Server, tm service.TendermintService, km keymanager.Backend, reg registry.Backend, rh roothash.Backend, s staking.Backend) {
	srv := &grpcServer{
		tendermintService: tm,
		keymanagerBackend: km,
		registryBackend:   reg,
		roothashBackend:   rh,
		stakingBackend:    s,
	}
	pb.RegisterGenesisServer(grpc, srv)
}
