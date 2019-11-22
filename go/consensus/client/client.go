// Package client implements a gRPC client for the consensus service.
package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	pb "github.com/oasislabs/oasis-core/go/grpc/consensus"
)

var _ api.ClientBackend = (*clientBackend)(nil)

// clientBackend is a consensus backend that can talk to a remote node over gRPC.
type clientBackend struct {
	grpc pb.ConsensusClient
}

func (b *clientBackend) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	_, err := b.grpc.SubmitTx(ctx, &pb.SubmitTxRequest{Tx: cbor.Marshal(tx)})
	return err
}

// New creates a new client consensus backend.
func New(c *grpc.ClientConn) (api.ClientBackend, error) {
	return &clientBackend{
		grpc: pb.NewConsensusClient(c),
	}, nil
}
