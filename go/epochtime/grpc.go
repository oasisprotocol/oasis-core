package epochtime

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"

	pb "github.com/oasislabs/ekiden/go/grpc/common"
	dbgPB "github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	_ pb.TimeSourceServer    = (*MockTimeSourceServer)(nil)
	_ dbgPB.DummyDebugServer = (*MockTimeSourceServer)(nil)

	serviceLogger = logging.GetLogger("dummy-debug")
)

// MockTimeSourceServer is a MockTimeSource exposed over gRPC, to be used
// for testing with arbitrary duration epochs broadcasted over a test network.
type MockTimeSourceServer struct {
	backend *MockTimeSource
}

// GetEpoch implements the corresponding gRPC call.
func (s *MockTimeSourceServer) GetEpoch(context.Context, *pb.EpochRequest) (*pb.EpochResponse, error) {
	epoch, elapsed := s.backend.GetEpoch()

	return &pb.EpochResponse{
		CurrentEpoch: uint64(epoch),
		WithinEpoch:  elapsed,
	}, nil
}

// WatchEpochs implements the corresponding gRPC call.
func (s *MockTimeSourceServer) WatchEpochs(req *pb.WatchEpochRequest, stream pb.TimeSource_WatchEpochsServer) error {
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
func (s *MockTimeSourceServer) SetEpoch(ctx context.Context, req *dbgPB.SetEpochRequest) (*dbgPB.SetEpochResponse, error) {
	epoch := EpochTime(req.GetEpoch())
	serviceLogger.Debug("set epoch",
		"epoch", epoch,
	)
	s.backend.SetEpoch(epoch, 0)

	return &dbgPB.SetEpochResponse{}, nil
}

// NewMockTimeSourceServer initializes and registers a new MockTimeSourceServer.
func NewMockTimeSourceServer(srv *grpc.Server) {
	s := &MockTimeSourceServer{
		backend: NewMockTimeSource(),
	}
	dbgPB.RegisterDummyDebugServer(srv, s)
}
