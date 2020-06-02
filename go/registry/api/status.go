package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// FreezeForever is an epoch that can be used to freeze a node for
// all (practical) time.
const FreezeForever epochtime.EpochTime = 0xffffffffffffffff

// NodeStatus is live status of a node.
type NodeStatus struct {
	// ExpirationProcessed is a flag specifying whether the node expiration
	// has already been processed.
	//
	// If you want to check whether a node has expired, check the node
	// descriptor directly instead of this flag.
	ExpirationProcessed bool `json:"expiration_processed"`
	// FreezeEndTime is the epoch when a frozen node can become unfrozen.
	//
	// After the specified epoch passes, this flag needs to be explicitly
	// cleared (set to zero) in order for the node to become unfrozen.
	FreezeEndTime epochtime.EpochTime `json:"freeze_end_time"`
}

// IsFrozen returns true if the node is currently frozen (prevented
// from being considered in scheduling decisions).
func (ns NodeStatus) IsFrozen() bool {
	return ns.FreezeEndTime > 0
}

// Unfreeze makes the node unfrozen.
func (ns *NodeStatus) Unfreeze() {
	ns.FreezeEndTime = 0
}

// UnfreezeNode is a request to unfreeze a frozen node.
type UnfreezeNode struct {
	NodeID signature.PublicKey `json:"node_id"`
}
