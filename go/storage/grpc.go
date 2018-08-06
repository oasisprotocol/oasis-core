package storage

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/oasislabs/ekiden/go/grpc/storage"
)

var _ pb.StorageServer = (*Server)(nil)

// Server is a Backend exposed over gRPC.
type Server struct {
	backend Backend
}

// Get implements the corresponding gRPC call.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	id := req.GetId()
	if len(id) != KeySize {
		return nil, errors.New("storage: malfored key")
	}

	var k Key
	copy(k[:], id)

	v, err := s.backend.Get(k)
	if err != nil {
		return nil, err
	}

	return &pb.GetResponse{Data: v}, nil
}

// Insert implements the corresponding gRPC call.
func (s *Server) Insert(ctx context.Context, req *pb.InsertRequest) (*pb.InsertResponse, error) {
	if err := s.backend.Insert(req.GetData(), req.GetExpiry()); err != nil {
		return nil, err
	}
	return &pb.InsertResponse{}, nil
}

// GetKeys implements the corresponding gRPC call.
func (s *Server) GetKeys(ctx context.Context, req *pb.GetKeysRequest) (*pb.GetKeysResponse, error) {
	kiVec, err := s.backend.GetKeys()
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

// NewServer intializes and registers a new Server backed by the provided
// Backend.
func NewServer(srv *grpc.Server, b Backend) {
	s := &Server{
		backend: b,
	}

	pb.RegisterStorageServer(srv, s)
}
