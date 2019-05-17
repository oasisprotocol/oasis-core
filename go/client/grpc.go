package client

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/client/indexer"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	pbClient "github.com/oasislabs/ekiden/go/grpc/client"
	pbEnRPC "github.com/oasislabs/ekiden/go/grpc/enclaverpc"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
)

var (
	_ pbClient.RuntimeServer   = (*grpcServer)(nil)
	_ pbEnRPC.EnclaveRpcServer = (*grpcServer)(nil)
)

type grpcServer struct {
	client *Client
}

// SubmitTx submits a new transaction to the committee leader.
func (s *grpcServer) SubmitTx(ctx context.Context, req *pbClient.SubmitTxRequest) (*pbClient.SubmitTxResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	result, err := s.client.SubmitTx(ctx, req.GetData(), id)
	if err != nil {
		return nil, err
	}

	response := pbClient.SubmitTxResponse{
		Result: result,
	}
	return &response, nil
}

func (s *grpcServer) WaitSync(ctx context.Context, req *pbClient.WaitSyncRequest) (*pbClient.WaitSyncResponse, error) {
	err := s.client.WaitSync(ctx)
	if err != nil {
		return nil, err
	}
	return &pbClient.WaitSyncResponse{}, nil
}

func (s *grpcServer) IsSynced(ctx context.Context, req *pbClient.IsSyncedRequest) (*pbClient.IsSyncedResponse, error) {
	synced, err := s.client.IsSynced(ctx)
	if err != nil {
		return nil, err
	}
	return &pbClient.IsSyncedResponse{
		Synced: synced,
	}, nil
}

func (s *grpcServer) WatchBlocks(req *pbClient.WatchBlocksRequest, stream pbClient.Runtime_WatchBlocksServer) error {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return err
	}

	ch, sub, err := s.client.WatchBlocks(stream.Context(), id)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil
			}

			blockHash := blk.Header.EncodedHash()
			pbBlk := &pbClient.WatchBlocksResponse{
				Block:     blk.MarshalCBOR(),
				BlockHash: blockHash[:],
			}
			if err := stream.Send(pbBlk); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *grpcServer) GetBlock(ctx context.Context, req *pbClient.GetBlockRequest) (*pbClient.GetBlockResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	blk, err := s.client.GetBlock(ctx, id, req.GetRound())
	if err != nil {
		if err == roothash.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, err.Error())
		}
		return nil, err
	}
	blockHash := blk.Header.EncodedHash()
	return &pbClient.GetBlockResponse{
		Block:     blk.MarshalCBOR(),
		BlockHash: blockHash[:],
	}, nil
}

func (s *grpcServer) GetTxn(ctx context.Context, req *pbClient.GetTxnRequest) (*pbClient.GetTxnResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	tx, err := s.client.GetTxn(ctx, id, req.GetRound(), req.GetIndex())
	if err != nil {
		if err == ErrBadIndexOrCorrupted {
			return nil, status.Errorf(codes.NotFound, err.Error())
		}
		return nil, err
	}

	return &pbClient.GetTxnResponse{
		Result: tx.MarshalCBOR(),
	}, nil
}

func (s *grpcServer) GetTxnByBlockHash(ctx context.Context, req *pbClient.GetTxnByBlockHashRequest) (*pbClient.GetTxnByBlockHashResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	var blockHash hash.Hash
	if err := blockHash.UnmarshalBinary(req.GetBlockHash()); err != nil {
		return nil, err
	}

	tx, err := s.client.GetTxnByBlockHash(ctx, id, blockHash, req.GetIndex())
	if err != nil {
		if err == ErrBadIndexOrCorrupted {
			return nil, status.Errorf(codes.NotFound, err.Error())
		}
		return nil, err
	}

	return &pbClient.GetTxnByBlockHashResponse{
		Result: tx.MarshalCBOR(),
	}, nil
}

func (s *grpcServer) GetTransactions(ctx context.Context, req *pbClient.GetTransactionsRequest) (*pbClient.GetTransactionsResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	var root hash.Hash
	if err := root.UnmarshalBinary(req.GetRoot()); err != nil {
		return nil, err
	}

	txns, err := s.client.GetTransactions(ctx, id, root)
	if err != nil {
		return nil, err
	}
	return &pbClient.GetTransactionsResponse{
		Txns: txns,
	}, nil
}

func (s *grpcServer) QueryBlock(ctx context.Context, req *pbClient.QueryBlockRequest) (*pbClient.QueryBlockResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	blk, err := s.client.QueryBlock(ctx, id, req.GetKey(), req.GetValue())
	if err != nil {
		if err == indexer.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, err.Error())
		}
		return nil, err
	}
	blockHash := blk.Header.EncodedHash()
	return &pbClient.QueryBlockResponse{
		Block:     blk.MarshalCBOR(),
		BlockHash: blockHash[:],
	}, nil
}

func (s *grpcServer) QueryTxn(ctx context.Context, req *pbClient.QueryTxnRequest) (*pbClient.QueryTxnResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	tx, err := s.client.QueryTxn(ctx, id, req.GetKey(), req.GetValue())
	if err != nil {
		if err == indexer.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, err.Error())
		}
		return nil, err
	}

	return &pbClient.QueryTxnResponse{
		Result: tx.MarshalCBOR(),
	}, nil
}

func (s *grpcServer) QueryTxns(ctx context.Context, req *pbClient.QueryTxnsRequest) (*pbClient.QueryTxnsResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	var query Query
	if err := query.UnmarshalCBOR(req.GetQuery()); err != nil {
		return nil, err
	}

	results, err := s.client.QueryTxns(ctx, id, query)
	if err != nil {
		return nil, err
	}
	if results == nil {
		results = make([]*TxnResult, 0)
	}

	return &pbClient.QueryTxnsResponse{
		Results: cbor.Marshal(results),
	}, nil
}

func (s *grpcServer) WaitBlockIndexed(ctx context.Context, req *pbClient.WaitBlockIndexedRequest) (*pbClient.WaitBlockIndexedResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetRuntimeId()); err != nil {
		return nil, err
	}

	err := s.client.WaitBlockIndexed(ctx, id, req.GetRound())
	if err != nil {
		return nil, err
	}
	return &pbClient.WaitBlockIndexedResponse{}, nil
}

func (s *grpcServer) CallEnclave(ctx context.Context, req *pbEnRPC.CallEnclaveRequest) (*pbEnRPC.CallEnclaveResponse, error) {
	rsp, err := s.client.CallEnclave(ctx, req.Endpoint, req.Payload)
	if err != nil {
		return nil, err
	}

	return &pbEnRPC.CallEnclaveResponse{Payload: rsp}, nil
}

// NewGRPCServer creates and registers a new GRPC server for the client interface.
func NewGRPCServer(srv *grpc.Server, client *Client) {
	s := &grpcServer{
		client: client,
	}
	pbClient.RegisterRuntimeServer(srv, s)
	pbEnRPC.RegisterEnclaveRpcServer(srv, s)
}
