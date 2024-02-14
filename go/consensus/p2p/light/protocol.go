// Package light implements a consensus light client protocol.
package light

import (
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/peermgmt"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
)

// LightProtocolID is a unique protocol identifier for the light client sync protocol.
const LightProtocolID = "light"

// LightProtocolVersion is the supported version of the light client sync protocol.
var LightProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// ProtocolID returns the light client sync protocol ID.
func ProtocolID(chainContext string) core.ProtocolID {
	return protocol.NewProtocolID(chainContext, LightProtocolID, LightProtocolVersion)
}

const (
	MethodGetLightBlock  = "GetLightBlock"
	MethodGetParameters  = "GetParameters"
	MethodSubmitEvidence = "SubmitEvidence"
)

func init() {
	peermgmt.RegisterNodeHandler(&peermgmt.NodeHandlerBundle{
		ProtocolsFn: func(_ *node.Node, chainContext string) []core.ProtocolID {
			return []core.ProtocolID{ProtocolID(chainContext)}
		},
	})
}
