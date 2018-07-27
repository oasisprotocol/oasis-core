package epochtime

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"

	pb "github.com/oasislabs/ekiden/go/grpc/common"
	dbgPB "github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	_ pb.TimeSourceServer    = (*TimeSourceServer)(nil)
	_ dbgPB.DummyDebugServer = (*TimeSourceServer)(nil)

	serviceLogger = logging.GetLogger("dummy-debug")
)

// TimeSourceServer is a TimeSource exposed over gRPC.
type TimeSourceServer struct {
	backend TimeSource
}

// GetEpoch implements the corresponding gRPC call.
func (s *TimeSourceServer) GetEpoch(context.Context, *pb.EpochRequest) (*pb.EpochResponse, error) {
	epoch, elapsed := s.backend.GetEpoch()

	return &pb.EpochResponse{
		CurrentEpoch: uint64(epoch),
		WithinEpoch:  elapsed,
	}, nil
}

// WatchEpochs implements the corresponding gRPC call.
func (s *TimeSourceServer) WatchEpochs(req *pb.WatchEpochRequest, stream pb.TimeSource_WatchEpochsServer) error {
	epochCh := s.backend.WatchEpochs()

	for {
		epoch, ok := <-epochCh
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

// SetEpoch implements the corresponding gRPC call.
func (s *TimeSourceServer) SetEpoch(ctx context.Context, req *dbgPB.SetEpochRequest) (*dbgPB.SetEpochResponse, error) {
	epoch := EpochTime(req.GetEpoch())
	serviceLogger.Debug("set epoch",
		"epoch", epoch,
	)

	mockTS := s.backend.(*MockTimeSource)
	mockTS.SetEpoch(epoch, 0)

	return &dbgPB.SetEpochResponse{}, nil
}

// NewTimeSourceServer initializes and registers a new TimeSourceServer.
func NewTimeSourceServer(srv *grpc.Server, timeSource TimeSource) {
	s := &TimeSourceServer{
		backend: timeSource,
	}
	pb.RegisterTimeSourceServer(srv, s)
	if _, ok := s.backend.(*MockTimeSource); ok {
		dbgPB.RegisterDummyDebugServer(srv, s)
	}
}
