package committee

import (
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// Ensure Node implements NodeHooks.
var _ committee.NodeHooks = (*Node)(nil)

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(bi *runtime.BlockInfo) {
	// Update our availability.
	n.nudgeAvailabilityLocked(false)

	// Drop blocks if the worker falls behind.
	select {
	case <-n.blockInfoCh:
	default:
	}

	// Non-blocking send.
	n.blockInfoCh <- bi
}
