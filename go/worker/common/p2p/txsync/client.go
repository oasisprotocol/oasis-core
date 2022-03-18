package txsync

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// Client is a transaction sync protocol client.
type Client interface {
	// GetTxs queries peers for transaction data.
	GetTxs(ctx context.Context, request *GetTxsRequest) (*GetTxsResponse, rpc.PeerFeedback, error)
}

type client struct {
	rc rpc.Client
}

func (c *client) GetTxs(ctx context.Context, request *GetTxsRequest) (*GetTxsResponse, rpc.PeerFeedback, error) {
	// Make sure we don't request too many transactions.
	if len(request.Txs) > MaxGetTxsCount {
		request.Txs = request.Txs[:MaxGetTxsCount]
	}
	txHashMap := make(map[hash.Hash]struct{}, len(request.Txs))
	for _, txHash := range request.Txs {
		txHashMap[txHash] = struct{}{}
	}

	var rsp GetTxsResponse
	pf, err := c.rc.Call(ctx, MethodGetTxs, request, &rsp, MaxGetTxsResponseTime,
		rpc.WithValidationFn(func(pf rpc.PeerFeedback) error {
			// If we received more transactions than we requested, this is an error.
			if len(rsp.Txs) > len(request.Txs) {
				pf.RecordFailure()
				return fmt.Errorf("more transactions than requested (expected: %d got: %d)", len(request.Txs), len(rsp.Txs))
			}

			// If we received transactions that we didn't request, this is an error.
			for _, tx := range rsp.Txs {
				txHash := hash.NewFromBytes(tx)
				if _, valid := txHashMap[txHash]; !valid {
					pf.RecordFailure()
					return fmt.Errorf("unsolicited transaction: %s", txHash)
				}
			}
			return nil
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

// NewClient creates a new transaction sync protocol client.
func NewClient(p2p rpc.P2P, runtimeID common.Namespace) Client {
	return &client{
		rc: rpc.NewClient(p2p, runtimeID, TxSyncProtocolID, TxSyncProtocolVersion),
	}
}
