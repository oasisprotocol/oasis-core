package txsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// minProtocolPeers is the minimum number of peers from the registry we want to have connected
	// for TxSync protocol.
	minProtocolPeers = 20

	// totalProtocolPeers is the number of peers we want to have connected for TxSync protocol.
	totalProtocolPeers = 40
)

// Client is a transaction sync protocol client.
type Client interface {
	// GetTxs queries peers for transaction data.
	GetTxs(ctx context.Context, request *GetTxsRequest) (*GetTxsResponse, error)
}

type client struct {
	rc  rpc.Client
	mgr rpc.PeerManager
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
	_, _, err := c.rc.CallMulti(ctx, c.mgr.GetBestPeers(), MethodGetTxs, request, rsp,
		rpc.WithAggregateFn(func(rawRsp any, pf rpc.PeerFeedback) bool {
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
func NewClient(p2p rpc.P2P, chainContext string, runtimeID common.Namespace) Client {
	pid := protocol.NewRuntimeProtocolID(chainContext, runtimeID, TxSyncProtocolID, TxSyncProtocolVersion)
	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.Host(), pid)
	rc.RegisterListener(mgr)

	p2p.RegisterProtocol(pid, minProtocolPeers, totalProtocolPeers)

	return &client{
		rc:  rc,
		mgr: mgr,
	}
}
