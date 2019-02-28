package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pb "github.com/oasislabs/ekiden/go/grpc/client"
)

var _ pb.RuntimeServer = (*grpcServer)(nil)

type grpcServer struct {
	client *Client
}

// SubmitTx submits a new transaction to the committee leader.
func (s *grpcServer) SubmitTx(ctx context.Context, req *pb.SubmitTxRequest) (*pb.SubmitTxResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	result, err := s.client.SubmitTx(ctx, req.GetData(), id)
	if err != nil {
		return nil, err
	}

	response := pb.SubmitTxResponse{
		Result: result,
	}
	return &response, nil
}

func (s *grpcServer) WaitSync(ctx context.Context, req *pb.WaitSyncRequest) (*pb.WaitSyncResponse, error) {
	err := s.client.WaitSync(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.WaitSyncResponse{}, nil
}

func (s *grpcServer) IsSynced(ctx context.Context, req *pb.IsSyncedRequest) (*pb.IsSyncedResponse, error) {
	synced, err := s.client.IsSynced(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.IsSyncedResponse{
		Synced: synced,
	}, nil
}

// NewGRPCServer creates and registers a new GRPC server for the client interface.
func NewGRPCServer(srv *grpc.Server, client *Client) {
	s := &grpcServer{
		client: client,
	}
	pb.RegisterRuntimeServer(srv, s)
}
