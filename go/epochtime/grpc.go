package epochtime

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/epochtime/api"

	pb "github.com/oasislabs/ekiden/go/grpc/common"
	dbgPB "github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	errIncompatibleBackend = errors.New("epochtime/grpc: incompatible backend for call")

	_ pb.TimeSourceServer    = (*grpcServer)(nil)
	_ dbgPB.DummyDebugServer = (*grpcServer)(nil)
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

func (s *grpcServer) SetEpoch(ctx context.Context, req *dbgPB.SetEpochRequest) (*dbgPB.SetEpochResponse, error) {
	mockTS, ok := s.backend.(api.SetableBackend)
	if !ok {
		return nil, errIncompatibleBackend
	}

	epoch := api.EpochTime(req.GetEpoch())
	err := mockTS.SetEpoch(ctx, epoch, 0)
	if err != nil {
		return nil, err
	}

	return &dbgPB.SetEpochResponse{}, nil
}

// NewGRPCServer initializes and registers a gRPC epochtime server
// backed by the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterTimeSourceServer(srv, s)
	if _, ok := s.backend.(api.SetableBackend); ok {
		dbgPB.RegisterDummyDebugServer(srv, s)
	}
}
