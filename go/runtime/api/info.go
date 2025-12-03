package api

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

// BlockInfo contains information related to the given runtime block.
type BlockInfo struct {
	// RuntimeBlock is the runtime block.
	RuntimeBlock *block.Block

	// ConsensusBlock is the consensus light block the runtime block belongs to.
	ConsensusBlock *consensus.LightBlock

	// IncomingMessages contains runtime's queued incoming messages.
	IncomingMessages []*message.IncomingMessage

	// Epoch is the epoch the runtime block belongs to.
	Epoch beacon.EpochTime
}

// DispatchInfo provides the context for checking, executing, or scheduling
// a batch of transactions.
type DispatchInfo struct {
	// BlockInfo holds information about the latest runtime block.
	BlockInfo *BlockInfo

	// ActiveDescriptor is the runtime descriptor currently in use for dispatch.
	ActiveDescriptor *registry.Runtime
}
