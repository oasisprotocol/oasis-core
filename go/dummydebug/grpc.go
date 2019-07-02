package dummydebug

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"

	dbgPB "github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

var (
	errIncompatibleBackend = errors.New("ticker/grpc: incompatible backend for call")

	_ dbgPB.DummyDebugServer = (*grpcServer)(nil)
)

type grpcServer struct {
	logger *logging.Logger

	timeSource ticker.Backend
	registry   registry.Backend
	scheduler  scheduler.Backend
}

func (s *grpcServer) AdvanceEpoch(ctx context.Context, req *dbgPB.AdvanceEpochRequest) (*dbgPB.AdvanceEpochResponse, error) {
	mockTS, ok := s.timeSource.(ticker.SetableBackend)
	if !ok {
		return nil, errIncompatibleBackend
	}

	epoch, err := s.scheduler.GetEpoch(ctx, 0)
	if err != nil {
		return nil, err
	}

	// TODO: make it not get stuck
	for {
		err := mockTS.DoTick(ctx)
		if err != nil {
			return nil, err
		}

		newEpoch, nerr := s.scheduler.GetEpoch(ctx, 0)
		if nerr != nil {
			return nil, nerr
		}
		if epoch != newEpoch {
			// After epoch changed, do one more tick.
			err = mockTS.DoTick(ctx)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	return &dbgPB.AdvanceEpochResponse{}, nil
}

func (s *grpcServer) WaitNodes(ctx context.Context, req *dbgPB.WaitNodesRequest) (*dbgPB.WaitNodesResponse, error) {
	ch, sub := s.registry.WatchNodes()
	defer sub.Close()

	// Check if there is already enough nodes registered. Note that this request may
	// fail if there is nothing committed yet, so ignore the error.
	nodes, err := s.registry.GetNodes(ctx)
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

				nodes, err = s.registry.GetNodes(ctx)
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
func NewGRPCServer(srv *grpc.Server, timeSource ticker.Backend, registry registry.Backend, scheduler scheduler.Backend) {
	s := &grpcServer{
		logger:     logging.GetLogger("dummydebug/grpc"),
		timeSource: timeSource,
		registry:   registry,
		scheduler:  scheduler,
	}
	dbgPB.RegisterDummyDebugServer(srv, s)
}
