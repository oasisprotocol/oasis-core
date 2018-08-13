package storage

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/storage/api"

	pb "github.com/oasislabs/ekiden/go/grpc/storage"
)

var _ pb.StorageServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	id := req.GetId()
	if len(id) != api.KeySize {
		return nil, errors.New("storage: malformed key")
	}

	var k api.Key
	copy(k[:], id)

	v, err := s.backend.Get(ctx, k)
	if err != nil {
		return nil, err
	}

	return &pb.GetResponse{Data: v}, nil
}

func (s *grpcServer) Insert(ctx context.Context, req *pb.InsertRequest) (*pb.InsertResponse, error) {
	if err := s.backend.Insert(ctx, req.GetData(), req.GetExpiry()); err != nil {
		return nil, err
	}
	return &pb.InsertResponse{}, nil
}

func (s *grpcServer) GetKeys(ctx context.Context, req *pb.GetKeysRequest) (*pb.GetKeysResponse, error) {
	kiVec, err := s.backend.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	var resp pb.GetKeysResponse
	for _, v := range kiVec {
		resp.Keys = append(resp.Keys, v.Key[:])
		resp.Expiry = append(resp.Expiry, uint64(v.Expiration))
	}

	return &resp, nil
}

// NewGRPCServer intializes and registers a grpc storage server backed
// by the provided Backend.
func NewGRPCServer(srv *grpc.Server, b api.Backend) {
	s := &grpcServer{
		backend: b,
	}

	pb.RegisterStorageServer(srv, s)
}
