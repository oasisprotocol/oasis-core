package txsync

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
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

func (s *service) handleGetTxs(request *GetTxsRequest) (*GetTxsResponse, error) {
	var rsp GetTxsResponse
	switch {
	case len(request.Txs) == 0:
		return &rsp, nil
	case len(request.Txs) > MaxGetTxsCount:
		// TODO: Could punish calling peer.
		request.Txs = request.Txs[:MaxGetTxsCount]
	default:
	}

	txs, _ := s.txPool.GetKnownBatch(request.Txs)
	rsp.Txs = make([][]byte, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		rsp.Txs = append(rsp.Txs, tx.Raw())
	}
	return &rsp, nil
}

// NewServer creates a new transaction sync protocol server.
func NewServer(chainContext string, runtimeID common.Namespace, txPool txpool.TransactionPool) rpc.Server {
	return rpc.NewServer(protocol.NewRuntimeProtocolID(chainContext, runtimeID, TxSyncProtocolID, TxSyncProtocolVersion), &service{txPool})
}
