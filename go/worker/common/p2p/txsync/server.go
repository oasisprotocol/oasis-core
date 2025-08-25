package txsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

type service struct {
	txPool txpool.TransactionPool
}

func (s *service) HandleRequest(_ context.Context, method string, body cbor.RawMessage) (any, error) {
	switch method {
	case MethodGetTxs:
		var rq GetTxsRequest
		if err := cbor.Unmarshal(body, &rq); err != nil {
			return nil, rpc.ErrBadRequest
		}

		return s.handleGetTxs(&rq)
	default:
		return nil, rpc.ErrMethodNotSupported
	}
}

func (s *service) handleGetTxs(req *GetTxsRequest) (*GetTxsResponse, error) {
	hashes := req.Hashes
	if len(hashes) > MaxGetTxsCount {
		// TODO: Could punish calling peer.
		hashes = hashes[:MaxGetTxsCount]
	}

	txs := make([][]byte, 0, len(hashes))
	for _, hash := range hashes {
		if tx, ok := s.txPool.Get(hash); ok {
			txs = append(txs, tx)
		}
	}

	return &GetTxsResponse{Txs: txs}, nil
}

// NewServer creates a new transaction sync protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, txPool txpool.TransactionPool) rpc.Server {
	return rpc.NewServer(ProtocolID(chainContext, runtimeID), &service{txPool})
}
