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

// Shutdownable is an interface the node presents for shutting itself down.
type Shutdownable interface {
	// RequestShutdown is the method called by the control server to trigger node shutdown.
	RequestShutdown() <-chan struct{}
}

type grpcServer struct {
	node       Shutdownable
	nodeClient *client.Client
}

func (s *grpcServer) RequestShutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	ch := s.node.RequestShutdown()
	if req.GetWait() {
		<-ch
	}
	return &pb.ShutdownResponse{}, nil
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

func NewGRPCServer(grpc *grpc.Server, node Shutdownable, nodeClient *client.Client) {
	s := &grpcServer{
		node:       node,
		nodeClient: nodeClient,
	}
	pb.RegisterControlServer(grpc.Server(), s)
}
