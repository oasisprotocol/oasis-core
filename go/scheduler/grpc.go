package scheduler

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/scheduler"
	"github.com/oasislabs/ekiden/go/scheduler/api"
)

var _ pb.SchedulerServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetCommittees(ctx context.Context, req *pb.CommitteeRequest) (*pb.CommitteeResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	committees, err := s.backend.GetCommittees(ctx, id)
	if err != nil {
		return nil, err
	}

	pbCommittees := make([]*pb.Committee, 0, len(committees))
	for _, v := range committees {
		pbCommittees = append(pbCommittees, v.ToProto())
	}

	return &pb.CommitteeResponse{Committee: pbCommittees}, nil
}

func (s *grpcServer) WatchCommittees(req *pb.WatchRequest, stream pb.Scheduler_WatchCommitteesServer) error {
	ch, sub := s.backend.WatchCommittees()
	defer sub.Close()

	for {
		var committee *api.Committee
		var ok bool

		select {
		case committee, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchResponse{
			Committee: committee.ToProto(),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewGRPCServer initializes and registers a gRPC scheduler server
// backed by the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterSchedulerServer(srv, s)
}
