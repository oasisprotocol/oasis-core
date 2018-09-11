package epochtime

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/epochtime/api"

	pb "github.com/oasislabs/ekiden/go/grpc/common"
)

var (
	_ pb.TimeSourceServer = (*grpcServer)(nil)
)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetEpoch(ctx context.Context, req *pb.EpochRequest) (*pb.EpochResponse, error) {
	epoch, elapsed, err := s.backend.GetEpoch(ctx)
	if err != nil {
		return nil, err
	}

	return &pb.EpochResponse{
		CurrentEpoch: uint64(epoch),
		WithinEpoch:  elapsed,
	}, nil
}

func (s *grpcServer) WatchEpochs(req *pb.WatchEpochRequest, stream pb.TimeSource_WatchEpochsServer) error {
	ch, sub := s.backend.WatchEpochs()
	defer sub.Close()

	for {
		var epoch api.EpochTime
		var ok bool

		select {
		case epoch, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchEpochResponse{
			CurrentEpoch: uint64(epoch),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewGRPCServer initializes and registers a gRPC epochtime server
// backed by the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterTimeSourceServer(srv, s)
}
