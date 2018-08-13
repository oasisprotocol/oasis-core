package beacon

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/beacon/api"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"

	pb "github.com/oasislabs/ekiden/go/grpc/beacon"
)

var _ pb.BeaconServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetBeacon(ctx context.Context, req *pb.BeaconRequest) (*pb.BeaconResponse, error) {
	b, err := s.backend.GetBeacon(ctx, epochtime.EpochTime(req.GetEpoch()))
	if err != nil {
		return nil, err
	}

	return &pb.BeaconResponse{Beacon: b}, nil
}

func (s *grpcServer) WatchBeacons(req *pb.WatchBeaconRequest, stream pb.Beacon_WatchBeaconsServer) error {
	ch, sub := s.backend.WatchBeacons()
	defer sub.Close()

	for {
		var ev *api.GenerateEvent
		var ok bool

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}
		resp := &pb.WatchBeaconResponse{
			Epoch:  uint64(ev.Epoch),
			Beacon: ev.Beacon,
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewGRPCServer initializes and registers a gRPC random beacon server
// backed by the provided Backend.
func NewGRPCServer(srv *grpc.Server, r api.Backend) {
	s := &grpcServer{
		backend: r,
	}
	pb.RegisterBeaconServer(srv, s)
}
