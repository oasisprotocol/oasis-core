// Package client implements a gRPC client for the staking service.
package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	pb "github.com/oasislabs/oasis-core/go/grpc/staking"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

var _ api.Backend = (*clientBackend)(nil)

// clientBackend is a staking backend that can talk to a remote node over gRPC.
type clientBackend struct {
	grpc pb.StakingClient
}

// Name is the name of the token.
func (b *clientBackend) Name() string {
	return api.TokenName
}

// Symbol is the symbol of the token.
func (b *clientBackend) Symbol() string {
	return api.TokenSymbol
}

// TotalSupply returns the total nmber of tokens.
func (b *clientBackend) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
	rsp, err := b.grpc.GetTotalSupply(ctx, &pb.GetTotalSupplyRequest{Height: height})
	if err != nil {
		return nil, err
	}

	var q quantity.Quantity
	if err := q.UnmarshalBinary(rsp.GetTotalSupply()); err != nil {
		return nil, fmt.Errorf("staking: malformed response: %w", err)
	}
	return &q, nil
}

// CommonPool returns the common pool balance.
func (b *clientBackend) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	rsp, err := b.grpc.GetCommonPool(ctx, &pb.GetCommonPoolRequest{Height: height})
	if err != nil {
		return nil, err
	}

	var q quantity.Quantity
	if err := q.UnmarshalBinary(rsp.GetCommonPool()); err != nil {
		return nil, fmt.Errorf("staking: malformed response: %w", err)
	}
	return &q, nil
}

// Threshold returns the specific staking threshold by kind.
func (b *clientBackend) Threshold(ctx context.Context, kind api.ThresholdKind, height int64) (*quantity.Quantity, error) {
	pbKind := pb.GetThresholdRequest_ThresholdKind(kind)

	rsp, err := b.grpc.GetThreshold(ctx, &pb.GetThresholdRequest{ThresholdKind: pbKind, Height: height})
	if err != nil {
		return nil, err
	}

	var q quantity.Quantity
	if err := q.UnmarshalBinary(rsp.GetThreshold()); err != nil {
		return nil, fmt.Errorf("staking: malformed response: %w", err)
	}
	return &q, nil
}

// Accounts returns the IDs of all accounts with a non-zero general
// or escrow balance.
func (b *clientBackend) Accounts(ctx context.Context, height int64) ([]signature.PublicKey, error) {
	rsp, err := b.grpc.GetAccounts(ctx, &pb.GetAccountsRequest{Height: height})
	if err != nil {
		return nil, err
	}

	var ids []signature.PublicKey
	for _, rawID := range rsp.GetIds() {
		var id signature.PublicKey
		if err := id.UnmarshalBinary(rawID); err != nil {
			return nil, fmt.Errorf("staking: malformed response: %w", err)
		}

		ids = append(ids, id)
	}
	return ids, nil
}

// AccountInfo returns the account descriptor for the given account.
func (b *clientBackend) AccountInfo(ctx context.Context, owner signature.PublicKey, height int64) (*api.Account, error) {
	id, _ := owner.MarshalBinary()

	rsp, err := b.grpc.GetAccountInfo(ctx, &pb.GetAccountInfoRequest{Id: id, Height: height})
	if err != nil {
		return nil, err
	}

	var account api.Account
	if err := cbor.Unmarshal(rsp.GetAccount(), &account); err != nil {
		return nil, fmt.Errorf("staking: malformed response: %w", err)
	}
	return &account, nil
}

// DebondingDelegations returns the list of debonding delegations for
// the given owner (delegator).
func (b *clientBackend) DebondingDelegations(ctx context.Context, owner signature.PublicKey, height int64) (map[signature.PublicKey][]*api.DebondingDelegation, error) {
	id, _ := owner.MarshalBinary()

	rsp, err := b.grpc.GetDebondingDelegations(ctx, &pb.GetDebondingDelegationsRequest{Owner: id, Height: height})
	if err != nil {
		return nil, err
	}

	var delegations map[signature.PublicKey][]*api.DebondingDelegation
	if err := cbor.Unmarshal(rsp.GetDelegations(), &delegations); err != nil {
		return nil, fmt.Errorf("staking: malformed response: %w", err)
	}
	return delegations, nil
}

// Transfer executes a SignedTransfer.
func (b *clientBackend) Transfer(ctx context.Context, signedXfer *api.SignedTransfer) error {
	_, err := b.grpc.Transfer(ctx, &pb.TransferRequest{SignedTransfer: cbor.Marshal(signedXfer)})
	if err != nil {
		return err
	}
	return nil
}

// Burn destroys tokens in the signing entity's balance.
func (b *clientBackend) Burn(ctx context.Context, signedBurn *api.SignedBurn) error {
	_, err := b.grpc.Burn(ctx, &pb.BurnRequest{SignedBurn: cbor.Marshal(signedBurn)})
	if err != nil {
		return err
	}
	return nil
}

// AddEscrow escrows the amount of tokens from the signer's balance.
func (b *clientBackend) AddEscrow(ctx context.Context, signedEscrow *api.SignedEscrow) error {
	_, err := b.grpc.AddEscrow(ctx, &pb.AddEscrowRequest{SignedEscrow: cbor.Marshal(signedEscrow)})
	if err != nil {
		return err
	}
	return nil
}

// ReclaimEscrow releases the quantity of the owner's escrow balance
// back into the owner's general balance.
func (b *clientBackend) ReclaimEscrow(ctx context.Context, signedReclaim *api.SignedReclaimEscrow) error {
	_, err := b.grpc.ReclaimEscrow(ctx, &pb.ReclaimEscrowRequest{SignedReclaim: cbor.Marshal(signedReclaim)})
	if err != nil {
		return err
	}
	return nil
}

// SubmitEvidence submits evidence of misbehavior.
func (b *clientBackend) SubmitEvidence(ctx context.Context, evidence api.Evidence) error {
	// TODO: Add gRPC method.
	return fmt.Errorf("staking: not yet implemented for client backend")
}

// WatchTransfers returns a channel that produces a stream of TranserEvent
// on all balance transfers.
func (b *clientBackend) WatchTransfers(ctx context.Context) (<-chan *api.TransferEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	cli, err := b.grpc.WatchTransfers(ctx, &pb.WatchTransfersRequest{})
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan *api.TransferEvent)
	go func() {
		defer close(ch)

		for {
			rsp, err := cli.Recv()
			if err != nil {
				return
			}

			var ev api.TransferEvent
			if err = cbor.Unmarshal(rsp.GetEvent(), &ev); err != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

// WatchBurns returns a channel of BurnEvent on token destruction.
func (b *clientBackend) WatchBurns(ctx context.Context) (<-chan *api.BurnEvent, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	cli, err := b.grpc.WatchBurns(ctx, &pb.WatchBurnsRequest{})
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan *api.BurnEvent)
	go func() {
		defer close(ch)

		for {
			rsp, err := cli.Recv()
			if err != nil {
				return
			}

			var ev api.BurnEvent
			if err = cbor.Unmarshal(rsp.GetEvent(), &ev); err != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

// WatchEscrows returns a channel that produces a stream of `*EscrowEvent`,
// `*TakeEscrowEvent`, and `*ReleaseEscrowEvent` when entities add to their
// escrow balance, get tokens deducted from their escrow balance, and
// have their escrow balance released into their general balance
// respectively.
func (b *clientBackend) WatchEscrows(ctx context.Context) (<-chan interface{}, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	cli, err := b.grpc.WatchEscrows(ctx, &pb.WatchEscrowsRequest{})
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan interface{})
	go func() {
		defer close(ch)

		for {
			rsp, err := cli.Recv()
			if err != nil {
				return
			}

			var ev interface{}
			switch rsp.GetEventType() {
			case pb.WatchEscrowsResponse_ADD:
				var e api.EscrowEvent
				if err = cbor.Unmarshal(rsp.GetEvent(), &e); err != nil {
					return
				}
				ev = &e
			case pb.WatchEscrowsResponse_TAKE:
				var e api.TakeEscrowEvent
				if err = cbor.Unmarshal(rsp.GetEvent(), &e); err != nil {
					return
				}
				ev = &e
			case pb.WatchEscrowsResponse_RECLAIM:
				var e api.ReclaimEscrowEvent
				if err = cbor.Unmarshal(rsp.GetEvent(), &e); err != nil {
					return
				}
				ev = &e
			default:
				return
			}

			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

// ToGenesis returns the genesis state at specified block height.
func (b *clientBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	// TODO: Add gRPC method.
	return nil, fmt.Errorf("staking: not yet implemented for client backend")
}

// Cleanup cleans up the backend.
func (b *clientBackend) Cleanup() {
}

// New creates a new client staking backend.
func New(c *grpc.ClientConn) (api.Backend, error) {
	return &clientBackend{
		grpc: pb.NewStakingClient(c),
	}, nil
}
