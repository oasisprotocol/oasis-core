package beacon

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/epochtime"

	pb "github.com/oasislabs/ekiden/go/grpc/beacon"
)

var _ pb.BeaconServer = (*RandomBeaconServer)(nil)

// RandomBeaconServer is a RandomBeacon exposed over gRPC.
type RandomBeaconServer struct {
	backend RandomBeacon
}

// GetBeacon implements the corresponding gRPC call.
func (s *RandomBeaconServer) GetBeacon(ctx context.Context, req *pb.BeaconRequest) (*pb.BeaconResponse, error) {
	b, err := s.backend.GetBeacon(epochtime.EpochTime(req.GetEpoch()))
	if err != nil {
		return nil, err
	}

	return &pb.BeaconResponse{Beacon: b}, nil
}

// WatchBeacons implements the corresponding gRPC call.
func (s *RandomBeaconServer) WatchBeacons(req *pb.WatchBeaconRequest, stream pb.Beacon_WatchBeaconsServer) error {
	evCh := s.backend.WatchBeacons()

	for {
		ev, ok := <-evCh
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

// NewRandomBeaconServer initializes and registers a new RandomBeaconServer
// backed by the provided RandomBeacon.
func NewRandomBeaconServer(srv *grpc.Server, r RandomBeacon) {
	s := &RandomBeaconServer{
		backend: r,
	}
	pb.RegisterBeaconServer(srv, s)
}
