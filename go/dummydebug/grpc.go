package dummydebug

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"

	dbgPB "github.com/oasislabs/oasis-core/go/grpc/dummydebug"
)

var (
	errIncompatibleBackend = errors.New("epochtime/grpc: incompatible backend for call")

	_ dbgPB.DummyDebugServer = (*grpcServer)(nil)
)

type grpcServer struct {
	logger *logging.Logger

	timeSource epochtime.Backend
	registry   registry.Backend
}

func (s *grpcServer) SetEpoch(ctx context.Context, req *dbgPB.SetEpochRequest) (*dbgPB.SetEpochResponse, error) {
	mockTS, ok := s.timeSource.(epochtime.SetableBackend)
	if !ok {
		return nil, errIncompatibleBackend
	}

	epoch := epochtime.EpochTime(req.GetEpoch())
	err := mockTS.SetEpoch(ctx, epoch)
	if err != nil {
		return nil, err
	}

	return &dbgPB.SetEpochResponse{}, nil
}

func (s *grpcServer) WaitNodes(ctx context.Context, req *dbgPB.WaitNodesRequest) (*dbgPB.WaitNodesResponse, error) {
	ch, sub := s.registry.WatchNodes()
	defer sub.Close()

	// Check if there is already enough nodes registered. Note that this request may
	// fail if there is nothing committed yet, so ignore the error.
	nodes, err := s.registry.GetNodes(ctx, 0)
	if err == nil {
		if len(nodes) >= int(req.GetNodes()) {
			return &dbgPB.WaitNodesResponse{}, nil
		}
	}

	// Wait for more nodes to register.
Loop:
	for {
		select {
		case ev := <-ch:
			if ev.IsRegistration {
				s.logger.Debug("WaitNodes: got new node registration event")

				nodes, err = s.registry.GetNodes(ctx, 0)
				if err != nil {
					return nil, err
				}

				if len(nodes) >= int(req.GetNodes()) {
					break Loop
				}
			}
		case <-ctx.Done():
			return nil, context.Canceled
		}
	}

	return &dbgPB.WaitNodesResponse{}, nil
}

// NewGRPCServer initializes and registers a gRPC dummydebug server
// backed by the provided backends.
func NewGRPCServer(srv *grpc.Server, timeSource epochtime.Backend, registry registry.Backend) {
	s := &grpcServer{
		logger:     logging.GetLogger("dummydebug/grpc"),
		timeSource: timeSource,
		registry:   registry,
	}
	dbgPB.RegisterDummyDebugServer(srv, s)
}
