package p2p

import (
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// KeyManagerProtocolID is a unique protocol identifier for the keymanager protocol.
const KeyManagerProtocolID = "keymanager"

// KeyManagerProtocolVersion is the supported version of the keymanager protocol.
var KeyManagerProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// Constants related to the GetDiff method.
const (
	MethodCallEnclave     = "CallEnclave"
	MaxCallEnclaveRetries = 15
)

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	Data []byte `json:"data"`
}

// CallEnclaveResponse is a response to a CallEnclave request.
type CallEnclaveResponse struct {
	Data []byte `json:"data"`
}

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleKeyManager) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = rpc.NewRuntimeProtocolID(rt.ID, KeyManagerProtocolID, KeyManagerProtocolVersion)
			}

			return protocols
		},
	})
}
