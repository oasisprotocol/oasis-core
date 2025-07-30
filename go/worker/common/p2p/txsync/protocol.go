package txsync

import (
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
)

// TxSyncProtocolID is a unique protocol identifier for the transaction sync protocol.
const TxSyncProtocolID = "txsync"

// TxSyncProtocolVersion is the supported version of the transaction sync protocol.
var TxSyncProtocolVersion = version.Version{Major: 2, Minor: 0, Patch: 0}

// ProtocolID returns the runtime transaction sync protocol ID.
func ProtocolID(chainContext string, runtimeID common.Namespace) core.ProtocolID {
	return protocol.NewRuntimeProtocolID(chainContext, runtimeID, TxSyncProtocolID, TxSyncProtocolVersion)
}

// Constants related to the GetTxs method.
const (
	MethodGetTxs   = "GetTxs"
	MaxGetTxsCount = 128
)

// GetTxsRequest is a GetTxs request.
type GetTxsRequest struct {
	Txs []hash.Hash `json:"txs"`
}

// GetTxsResponse is a response to a GetTxs request.
type GetTxsResponse struct {
	Txs [][]byte `json:"txs,omitempty"`
}

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleComputeWorker) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = ProtocolID(chainContext, rt.ID)
			}

			return protocols
		},
	})
}
