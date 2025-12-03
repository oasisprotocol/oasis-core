package committee

import (
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// Ensure Node implements NodeHooks.
var _ committee.NodeHooks = (*Node)(nil)

// HandleNewDispatchInfo implements NodeHooks.
func (n *Node) HandleNewDispatchInfo(di *runtime.DispatchInfo) {
	// Update our availability.
	n.nudgeAvailabilityLocked(false)

	// Drop if the worker falls behind.
	select {
	case <-n.dispatchInfoCh:
	default:
	}

	// Non-blocking send.
	n.dispatchInfoCh <- di
}
