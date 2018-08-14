package roothash

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/roothash"
	"github.com/oasislabs/ekiden/go/roothash/api"
)

var _ pb.RootHashServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetLatestBlock(ctx context.Context, req *pb.LatestBlockRequest) (*pb.LatestBlockResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return nil, err
	}

	blk, err := s.backend.GetLatestBlock(ctx, id)
	if err != nil {
		return nil, err
	}

	return &pb.LatestBlockResponse{Block: blk.ToProto()}, nil
}

func (s *grpcServer) GetBlocks(req *pb.BlockRequest, stream pb.RootHash_GetBlocksServer) error {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return err
	}

	ch, sub, err := s.backend.WatchBlocks(id)
	if err != nil {
		return err
	}
	defer sub.Close()

	return grpcSendBlocks(ch, stream)
}

func (s *grpcServer) GetBlocksSince(req *pb.BlockSinceRequest, stream pb.RootHash_GetBlocksSinceServer) error {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return err
	}

	var round api.Round
	if err := round.UnmarshalBinary(req.GetRound()); err != nil {
		return err
	}

	ch, sub, err := s.backend.WatchBlocksSince(id, round)
	if err != nil {
		return err
	}
	defer sub.Close()

	return grpcSendBlocks(ch, stream)
}

func (s *grpcServer) GetEvents(req *pb.EventRequest, stream pb.RootHash_GetEventsServer) error {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return err
	}

	ch, sub, err := s.backend.WatchEvents(id)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		var ev *api.Event
		var ok bool

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		var pev pb.Event
		if ev.DiscrepancyDetected != nil {
			pev.Event = &pb.Event_DiscrepancyDetected_{
				DiscrepancyDetected: &pb.Event_DiscrepancyDetected{
					BatchHash: append([]byte{}, ev.DiscrepancyDetected[:]...),
				},
			}
		} else if ev.RoundFailed != nil {
			pev.Event = &pb.Event_RoundFailed_{
				RoundFailed: &pb.Event_RoundFailed{
					Error: ev.RoundFailed.Error(),
				},
			}
		} else {
			panic("BUG: invalid/malformed event")
		}

		resp := &pb.EventResponse{
			Event: &pev,
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetContractId()); err != nil {
		return nil, err
	}

	var commit api.Commitment
	if err := commit.FromProto(req.Commitment); err != nil {
		return nil, err
	}

	if err := s.backend.Commit(ctx, id, &commit); err != nil {
		return nil, err
	}

	return &pb.CommitResponse{}, nil
}

// NewGRPCServer initializes and registers a gRPC root hash server
// backed by the provided backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterRootHashServer(srv, s)
}

type blockSender interface {
	Context() context.Context
	Send(*pb.BlockResponse) error
}

func grpcSendBlocks(ch <-chan *api.Block, stream blockSender) error {
	for {
		var blk *api.Block
		var ok bool

		select {
		case blk, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.BlockResponse{
			Block: blk.ToProto(),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}
