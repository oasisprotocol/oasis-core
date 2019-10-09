package staking

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	pb "github.com/oasislabs/oasis-core/go/grpc/staking"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

var _ pb.StakingServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetName(ctx context.Context, req *pb.GetNameRequest) (*pb.GetNameResponse, error) {
	return &pb.GetNameResponse{
		Name: s.backend.Name(),
	}, nil
}

func (s *grpcServer) GetSymbol(ctx context.Context, req *pb.GetSymbolRequest) (*pb.GetSymbolResponse, error) {
	return &pb.GetSymbolResponse{
		Symbol: s.backend.Symbol(),
	}, nil
}

func (s *grpcServer) GetTotalSupply(ctx context.Context, req *pb.GetTotalSupplyRequest) (*pb.GetTotalSupplyResponse, error) {
	totalSupply, err := s.backend.TotalSupply(ctx)
	if err != nil {
		return nil, err
	}

	var resp pb.GetTotalSupplyResponse
	resp.TotalSupply, _ = totalSupply.MarshalBinary()

	return &resp, nil
}

func (s *grpcServer) GetCommonPool(ctx context.Context, req *pb.GetCommonPoolRequest) (*pb.GetCommonPoolResponse, error) {
	commonPool, err := s.backend.CommonPool(ctx)
	if err != nil {
		return nil, err
	}

	var resp pb.GetCommonPoolResponse
	resp.CommonPool, _ = commonPool.MarshalBinary()

	return &resp, nil
}

func (s *grpcServer) GetThreshold(ctx context.Context, req *pb.GetThresholdRequest) (*pb.GetThresholdResponse, error) {
	var kind api.ThresholdKind
	switch req.GetThresholdKind() {
	case pb.GetThresholdRequest_ENTITY:
		kind = api.KindEntity
	case pb.GetThresholdRequest_VALIDATOR:
		kind = api.KindValidator
	case pb.GetThresholdRequest_COMPUTE:
		kind = api.KindCompute
	case pb.GetThresholdRequest_STORAGE:
		kind = api.KindStorage
	default:
		return nil, fmt.Errorf("staking/grpc: invalid threshold kind: %v", req.GetThresholdKind())
	}

	qty, err := s.backend.Threshold(ctx, kind)
	if err != nil {
		return nil, err
	}

	var resp pb.GetThresholdResponse
	resp.Threshold, _ = qty.MarshalBinary()

	return &resp, nil
}

func (s *grpcServer) GetAccounts(ctx context.Context, req *pb.GetAccountsRequest) (*pb.GetAccountsResponse, error) {
	accounts, err := s.backend.Accounts(ctx)
	if err != nil {
		return nil, err
	}

	var resp pb.GetAccountsResponse
	for _, v := range accounts {
		id, _ := v.MarshalBinary()
		resp.Ids = append(resp.Ids, id)
	}

	return &resp, nil
}

func (s *grpcServer) GetAccountInfo(ctx context.Context, req *pb.GetAccountInfoRequest) (*pb.GetAccountInfoResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	account, err := s.backend.AccountInfo(ctx, id)
	if err != nil {
		return nil, err
	}

	var resp pb.GetAccountInfoResponse
	resp.GeneralBalance, _ = account.General.Balance.MarshalBinary()
	resp.EscrowBalance, _ = account.Escrow.Balance.MarshalBinary()
	resp.Nonce = account.General.Nonce

	return &resp, nil
}

func (s *grpcServer) Transfer(ctx context.Context, req *pb.TransferRequest) (*pb.TransferResponse, error) {
	var signedTransfer api.SignedTransfer
	if err := cbor.Unmarshal(req.GetSignedTransfer(), &signedTransfer); err != nil {
		return nil, err
	}

	if err := s.backend.Transfer(ctx, &signedTransfer); err != nil {
		return nil, err
	}

	return &pb.TransferResponse{}, nil
}

func (s *grpcServer) Burn(ctx context.Context, req *pb.BurnRequest) (*pb.BurnResponse, error) {
	var signedBurn api.SignedBurn
	if err := cbor.Unmarshal(req.GetSignedBurn(), &signedBurn); err != nil {
		return nil, err
	}

	if err := s.backend.Burn(ctx, &signedBurn); err != nil {
		return nil, err
	}

	return &pb.BurnResponse{}, nil
}

func (s *grpcServer) AddEscrow(ctx context.Context, req *pb.AddEscrowRequest) (*pb.AddEscrowResponse, error) {
	var signedEscrow api.SignedEscrow
	if err := cbor.Unmarshal(req.GetSignedEscrow(), &signedEscrow); err != nil {
		return nil, err
	}

	if err := s.backend.AddEscrow(ctx, &signedEscrow); err != nil {
		return nil, err
	}

	return &pb.AddEscrowResponse{}, nil
}

func (s *grpcServer) ReclaimEscrow(ctx context.Context, req *pb.ReclaimEscrowRequest) (*pb.ReclaimEscrowResponse, error) {
	var signedReclaim api.SignedReclaimEscrow
	if err := cbor.Unmarshal(req.GetSignedReclaim(), &signedReclaim); err != nil {
		return nil, err
	}

	if err := s.backend.ReclaimEscrow(ctx, &signedReclaim); err != nil {
		return nil, err
	}

	return &pb.ReclaimEscrowResponse{}, nil
}

func (s *grpcServer) WatchTransfers(req *pb.WatchTransfersRequest, stream pb.Staking_WatchTransfersServer) error {
	ch, sub := s.backend.WatchTransfers()
	defer sub.Close()

	for {
		var (
			ev *api.TransferEvent
			ok bool
		)

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchTransfersResponse{
			Event: cbor.Marshal(ev),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) WatchBurns(req *pb.WatchBurnsRequest, stream pb.Staking_WatchBurnsServer) error {
	ch, sub := s.backend.WatchBurns()
	defer sub.Close()

	for {
		var (
			ev *api.BurnEvent
			ok bool
		)

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchBurnsResponse{
			Event: cbor.Marshal(ev),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) WatchEscrows(req *pb.WatchEscrowsRequest, stream pb.Staking_WatchEscrowsServer) error {
	ch, sub := s.backend.WatchEscrows()
	defer sub.Close()

	for {
		var (
			ev interface{}
			ok bool
		)

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchEscrowsResponse{
			Event: cbor.Marshal(ev),
		}
		switch ev.(type) {
		case *api.EscrowEvent:
			resp.EventType = pb.WatchEscrowsResponse_ADD
		case *api.TakeEscrowEvent:
			resp.EventType = pb.WatchEscrowsResponse_TAKE
		case *api.ReclaimEscrowEvent:
			resp.EventType = pb.WatchEscrowsResponse_RECLAIM
		default:
			return fmt.Errorf("staking/grpc: unsupported escrow event type: '%T'", ev)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewGRPCServer initializes and registers a new gRPC staking server backed
// by the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterStakingServer(srv, s)
}
