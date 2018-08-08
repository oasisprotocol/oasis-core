package scheduler

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/scheduler"
)

var _ pb.SchedulerServer = (*SchedulerServer)(nil)

// SchedulerServer is a Scheduler exposed over gRPC.
type SchedulerServer struct { //nolint:golint
	backend Scheduler
}

// GetCommittees implements the corresponding gRPC call.
func (s *SchedulerServer) GetCommittees(ctx context.Context, req *pb.CommitteeRequest) (*pb.CommitteeResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return nil, err
	}

	committees := s.backend.GetCommittees(id)
	pbCommittees := make([]*pb.Committee, 0, len(committees))
	for _, v := range committees {
		pbCommittees = append(pbCommittees, v.ToProto())
	}

	return &pb.CommitteeResponse{Committee: pbCommittees}, nil
}

// WatchCommittees implements the corresponding gRPC call.
func (s *SchedulerServer) WatchCommittees(req *pb.WatchRequest, stream pb.Scheduler_WatchCommitteesServer) error {
	ch, sub := s.backend.WatchCommittees()
	defer sub.Close()

	for {
		committee, ok := <-ch
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

// NewSchedulerServer initializes and registers a new SchedulerServer backed
// by the provided Scheduler.
func NewSchedulerServer(srv *grpc.Server, sched Scheduler) {
	s := &SchedulerServer{
		backend: sched,
	}
	pb.RegisterSchedulerServer(srv, s)
}
