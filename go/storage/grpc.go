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

func (s *grpcServer) GetBatch(ctx context.Context, req *pb.GetBatchRequest) (*pb.GetBatchResponse, error) {
	var keys []api.Key
	for _, id := range req.GetIds() {
		if len(id) != api.KeySize {
			return nil, errors.New("storage: malformed key")
		}

		var k api.Key
		copy(k[:], id)
		keys = append(keys, k)
	}

	values, err := s.backend.GetBatch(ctx, keys)
	if err != nil {
		return nil, err
	}

	return &pb.GetBatchResponse{Data: values}, nil
}

func (s *grpcServer) Insert(ctx context.Context, req *pb.InsertRequest) (*pb.InsertResponse, error) {
	if err := s.backend.Insert(ctx, req.GetData(), req.GetExpiry()); err != nil {
		return nil, err
	}
	return &pb.InsertResponse{}, nil
}

func (s *grpcServer) InsertBatch(ctx context.Context, req *pb.InsertBatchRequest) (*pb.InsertBatchResponse, error) {
	var values []api.Value
	for _, item := range req.GetItems() {
		values = append(values, api.Value{
			Data:       item.GetData(),
			Expiration: item.GetExpiry(),
		})
	}

	if err := s.backend.InsertBatch(ctx, values); err != nil {
		return nil, err
	}

	return &pb.InsertBatchResponse{}, nil
}

func (s *grpcServer) GetKeys(req *pb.GetKeysRequest, stream pb.Storage_GetKeysServer) error {
	ch, err := s.backend.GetKeys(stream.Context())
	if err != nil {
		return err
	}

	for {
		var ki *api.KeyInfo
		var ok bool

		select {
		case ki, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.GetKeysResponse{
			Key:    ki.Key[:],
			Expiry: uint64(ki.Expiration),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewGRPCServer intializes and registers a grpc storage server backed
// by the provided Backend.
func NewGRPCServer(srv *grpc.Server, b api.Backend) {
	s := &grpcServer{
		backend: b,
	}

	pb.RegisterStorageServer(srv, s)
}
