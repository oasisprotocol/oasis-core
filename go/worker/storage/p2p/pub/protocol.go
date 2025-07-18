package pub

import (
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// StoragePubProtocolID is a unique protocol identifier for the storage pub protocol.
const StoragePubProtocolID = "storagepub"

// StoragePubProtocolVersion is the supported version of the storage pub protocol.
var StoragePubProtocolVersion = version.Version{Major: 2, Minor: 0, Patch: 0}

// ProtocolID returns the runtime storage pub protocol ID.
func ProtocolID(chainContext string, runtimeID common.Namespace) core.ProtocolID {
	return protocol.NewRuntimeProtocolID(chainContext, runtimeID, StoragePubProtocolID, StoragePubProtocolVersion)
}

// Constants related to the Get method.
const (
	MethodGet = "Get"
)

// GetRequest is a Get request.
type GetRequest = syncer.GetRequest

// ProofResponse is a response to Get/GetPrefixes/Iterate containing a proof.
type ProofResponse = syncer.ProofResponse

// Constants related to the GetPrefixes method.
const (
	MethodGetPrefixes = "GetPrefixes"
)

// GetPrefixesRequest is a GetPrefixes request.
type GetPrefixesRequest = syncer.GetPrefixesRequest

// Constants related to the Iterate method.
const (
	MethodIterate = "Iterate"
)

// IterateRequest is an Iterate request.
type IterateRequest = syncer.IterateRequest

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(n *node.Node, chainContext string) []core.ProtocolID {
			if !n.HasRoles(node.RoleStorageRPC) {
				return []core.ProtocolID{}
			}

			protocols := make([]core.ProtocolID, len(n.Runtimes))
			for i, rt := range n.Runtimes {
				protocols[i] = protocol.NewRuntimeProtocolID(chainContext, rt.ID, StoragePubProtocolID, StoragePubProtocolVersion)
			}

			return protocols
		},
	})
}
