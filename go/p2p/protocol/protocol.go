package protocol

import (
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

type protocolRegistry struct {
	mu        sync.Mutex
	protocols map[core.ProtocolID]struct{}
}

func newProtocolRegistry() *protocolRegistry {
	return &protocolRegistry{
		protocols: make(map[core.ProtocolID]struct{}),
	}
}

var registry = newProtocolRegistry()

// ValidateProtocolID panics if the protocol id is not unique.
func ValidateProtocolID(p core.ProtocolID) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if _, ok := registry.protocols[p]; ok {
		panic(fmt.Sprintf("p2p/protocol: protocol or topic with name '%s' already exists", p))
	}
	registry.protocols[p] = struct{}{}
}

// ValidateTopicID panics if the topic id is not unique.
func ValidateTopicID(topic string) {
	ValidateProtocolID(core.ProtocolID(topic))
}

// NewProtocolID generates a protocol identifier for a consensus P2P protocol.
func NewProtocolID(chainContext string, protocolID string, version version.Version) protocol.ID {
	return protocol.ID(fmt.Sprintf("/oasis/%s/%s/%s", chainContext, protocolID, version.MaskNonMajor()))
}

// NewRuntimeProtocolID generates a protocol identifier for a protocol supported for a specific
// runtime. This makes it so that one doesn't need additional checks to ensure that a peer supports
// the given protocol for the given runtime.
func NewRuntimeProtocolID(chainContext string, runtimeID common.Namespace, protocolID string, version version.Version) protocol.ID {
	return protocol.ID(fmt.Sprintf("/oasis/%s/%s/%s/%s", chainContext, protocolID, runtimeID.Hex(), version.MaskNonMajor()))
}

// NewTopicIDForRuntime constructs topic id from the given parameters.
func NewTopicIDForRuntime(chainContext string, runtimeID common.Namespace, kind api.TopicKind, version version.Version) string {
	return fmt.Sprintf("oasis/%s/%s/%s/%s", chainContext, kind, runtimeID.String(), version.MaskNonMajor())
}

// NewTopicKindTxID constructs topic id from the given parameters.
func NewTopicKindTxID(chainContext string, runtimeID common.Namespace) string {
	return NewTopicIDForRuntime(chainContext, runtimeID, api.TopicKindTx, version.RuntimeCommitteeProtocol)
}

// NewTopicKindCommitteeID constructs topic id from the given parameters.
func NewTopicKindCommitteeID(chainContext string, runtimeID common.Namespace) string {
	return NewTopicIDForRuntime(chainContext, runtimeID, api.TopicKindCommittee, version.RuntimeCommitteeProtocol)
}
