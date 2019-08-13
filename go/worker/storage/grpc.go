package storage

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc"
	pb "github.com/oasislabs/ekiden/go/grpc/storage"
	"github.com/oasislabs/ekiden/go/worker/storage/committee"
)

var (
	_ pb.StorageWorkerServer = (*grpcServer)(nil)

	// ErrRuntimeNotFound is the error returned when the called references an unknown runtime.
	ErrRuntimeNotFound = errors.New("worker/storage: runtime not found")
)

type grpcServer struct {
	w *Worker
}

func (s *grpcServer) GetLastSyncedRound(ctx context.Context, req *pb.GetLastSyncedRoundRequest) (*pb.GetLastSyncedRoundResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	var node *committee.Node
	node, ok := s.w.runtimes[id.ToMapKey()]
	if !ok {
		return nil, ErrRuntimeNotFound
	}

	round, ioRoot, stateRoot := node.GetLastSynced()

	resp := &pb.GetLastSyncedRoundResponse{
		Round:     round,
		IoRoot:    ioRoot.MarshalCBOR(),
		StateRoot: stateRoot.MarshalCBOR(),
	}
	return resp, nil
}

func newGRPCServer(grpc *grpc.Server, w *Worker) {
	s := &grpcServer{w}
	pb.RegisterStorageWorkerServer(grpc.Server(), s)
}
