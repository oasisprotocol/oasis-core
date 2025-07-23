package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

// KeyManagerProtocolID is a unique protocol identifier for the keymanager protocol.
const KeyManagerProtocolID = "keymanager"

// KeyManagerProtocolVersion is the supported version of the keymanager protocol.
var KeyManagerProtocolVersion = version.Version{Major: 2, Minor: 0, Patch: 0}

// ProtocolID returns the runtime keymanager protocol ID.
func ProtocolID(chainContext string, runtimeID common.Namespace) core.ProtocolID {
	return protocol.NewRuntimeProtocolID(chainContext, runtimeID, KeyManagerProtocolID, KeyManagerProtocolVersion)
}

// Constants related to the CallEnclave method.
const (
	MethodCallEnclave        = "CallEnclave"
	MethodCallEnclaveTimeout = 3 * time.Second
)

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	Data []byte          `json:"data"`
	Kind enclaverpc.Kind `json:"kind,omitempty"`
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
				protocols[i] = ProtocolID(chainContext, rt.ID)
			}

			return protocols
		},
	})
}
