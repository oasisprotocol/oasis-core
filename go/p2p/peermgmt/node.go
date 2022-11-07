package peermgmt

import (
	"sync"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// NodeHandler is an interface for a handler to return protocols and topics supported by a node.
type NodeHandler interface {
	// Protocols returns the ids of the protocols the node supports on the given chain.
	Protocols(n *node.Node, chainContext string) []core.ProtocolID

	// Topics returns the ids of the topics the node supports on the given chain.
	Topics(n *node.Node, chainContext string) []string
}

// NodeHandlerBundle implements NodeHandler by calling any of the functions set on it, and returning
// default values if they are unset.
type NodeHandlerBundle struct {
	ProtocolsFn func(n *node.Node, chainContext string) []core.ProtocolID
	TopicsFn    func(n *node.Node, chainContext string) []string
}

var _ NodeHandler = (*NodeHandlerBundle)(nil)

// Protocols calls ProtocolsFn if set or returns an empty list of protocols.
func (b *NodeHandlerBundle) Protocols(n *node.Node, chainContext string) []core.ProtocolID {
	if b.ProtocolsFn != nil {
		return b.ProtocolsFn(n, chainContext)
	}
	return []core.ProtocolID{}
}

// Topics calls TopicsFn if set or returns an empty list of topics.
func (b *NodeHandlerBundle) Topics(n *node.Node, chainContext string) []string {
	if b.TopicsFn != nil {
		return b.TopicsFn(n, chainContext)
	}
	return []string{}
}

var nodeHandlers struct {
	sync.RWMutex
	l []NodeHandler
}

// RegisterNodeHandler registers a node handler.
func RegisterNodeHandler(h NodeHandler) {
	nodeHandlers.Lock()
	defer nodeHandlers.Unlock()

	nodeHandlers.l = append(nodeHandlers.l, h)
}
