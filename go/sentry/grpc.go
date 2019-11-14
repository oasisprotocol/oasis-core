package sentry

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/node"
	pb "github.com/oasislabs/oasis-core/go/grpc/sentry"
	"github.com/oasislabs/oasis-core/go/sentry/api"
)

var _ pb.SentryServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetConsensusAddresses(ctx context.Context, req *pb.GetConsensusAddressesRequest) (*pb.GetConsensusAddressesResponse, error) {
	addresses, err := s.backend.GetConsensusAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("sentry: error obtaining public addresses: %w", err)
	}
	return &pb.GetConsensusAddressesResponse{
		Addresses: node.ToProtoConsensusAddresses(addresses),
	}, nil
}

// NewGRPCServer initializes and registers a new gRPC sentry server backend by
// the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterSentryServer(srv, s)
}
