package txsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// Client is a transaction sync protocol client.
type Client interface {
	// GetTxs queries peers for transaction data.
	GetTxs(ctx context.Context, request *GetTxsRequest) (*GetTxsResponse, error)
}

type client struct {
	rc rpc.Client
}

func (c *client) GetTxs(ctx context.Context, request *GetTxsRequest) (*GetTxsResponse, error) {
	// Make sure we don't request too many transactions.
	if len(request.Txs) > MaxGetTxsCount {
		request.Txs = request.Txs[:MaxGetTxsCount]
	}
	txHashMap := make(map[hash.Hash]struct{}, len(request.Txs))
	for _, txHash := range request.Txs {
		txHashMap[txHash] = struct{}{}
	}
	resultTxMap := make(map[hash.Hash][]byte)

	var rsp GetTxsResponse
	_, _, err := c.rc.CallMulti(ctx, MethodGetTxs, request, rsp, MaxGetTxsResponseTime, MaxGetTxsParallelRequests,
		rpc.WithAggregateFn(func(rawRsp interface{}, pf rpc.PeerFeedback) bool {
			rsp := rawRsp.(*GetTxsResponse)

			// If we received more transactions than we requested, this is an error.
			if len(rsp.Txs) > len(request.Txs) {
				pf.RecordFailure()
				return true
			}

			// If we received transactions that we didn't request, this is an error.
			for _, tx := range rsp.Txs {
				txHash := hash.NewFromBytes(tx)
				if _, valid := txHashMap[txHash]; !valid {
					pf.RecordFailure()
					return true
				}

				resultTxMap[txHash] = tx
			}

			if len(rsp.Txs) > 0 {
				pf.RecordSuccess()
			}

			// Check if we have everything and stop early.
			return len(resultTxMap) != len(txHashMap)
		}))
	if err != nil {
		return nil, err
	}

	rsp.Txs = make([][]byte, 0, len(resultTxMap))
	for _, tx := range resultTxMap {
		rsp.Txs = append(rsp.Txs, tx)
	}
	return &rsp, nil
}

// NewClient creates a new transaction sync protocol client.
func NewClient(p2p rpc.P2P, runtimeID common.Namespace) Client {
	return &client{
		rc: rpc.NewClient(p2p, runtimeID, TxSyncProtocolID, TxSyncProtocolVersion),
	}
}
