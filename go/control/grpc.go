package control

import (
	"context"

	"github.com/oasislabs/oasis-core/go/client"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	pb "github.com/oasislabs/oasis-core/go/grpc/control"
)

var (
	_ pb.ControlServer = (*grpcServer)(nil)
)

type grpcServer struct {
	nodeClient *client.Client
}

func (s *grpcServer) WaitSync(ctx context.Context, req *pb.WaitSyncRequest) (*pb.WaitSyncResponse, error) {
	err := s.nodeClient.WaitSync(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.WaitSyncResponse{}, nil
}

func (s *grpcServer) IsSynced(ctx context.Context, req *pb.IsSyncedRequest) (*pb.IsSyncedResponse, error) {
	synced, err := s.nodeClient.IsSynced(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.IsSyncedResponse{
		Synced: synced,
	}, nil
}

func NewGRPCServer(grpc *grpc.Server, nodeClient *client.Client) {
	s := &grpcServer{
		nodeClient: nodeClient,
	}
	pb.RegisterControlServer(grpc.Server(), s)
}
