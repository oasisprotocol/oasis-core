package txsync

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// TxSyncProtocolID is a unique protocol identifier for the transaction sync protocol.
const TxSyncProtocolID = "txsync"

// TxSyncProtocolVersion is the supported version of the transaction sync protocol.
var TxSyncProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// Constants related to the GetTxs method.
const (
	MethodGetTxs              = "GetTxs"
	MaxGetTxsResponseTime     = 5 * time.Second
	MaxGetTxsCount            = 128
	MaxGetTxsParallelRequests = 5
)

// GetTxsRequest is a GetTxs request.
type GetTxsRequest struct {
	Txs []hash.Hash `json:"txs"`
}

// GetTxsResponse is a response to a GetTxs request.
type GetTxsResponse struct {
	Txs [][]byte `json:"txs,omitempty"`
}
