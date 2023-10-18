package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crash"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// Ensure Node implements NodeHooks.
var _ committee.NodeHooks = (*Node)(nil)

// HandlePeerTx implements NodeHooks.
func (n *Node) HandlePeerTx(context.Context, []byte) error {
	// Nothing to do here.
	return nil
}

// HandleEpochTransitionLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleEpochTransitionLocked(*committee.EpochSnapshot) {
	// Nothing to do here.
}

// HandleNewBlockEarlyLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(*runtime.BlockInfo) {
	crash.Here(crashPointRoothashReceiveAfter)

	// Update our availability.
	n.nudgeAvailabilityLocked(false)
}

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(bi *runtime.BlockInfo) {
	// Drop blocks if the worker falls behind.
	select {
	case <-n.blockInfoCh:
	default:
	}

	// Non-blocking send.
	n.blockInfoCh <- bi
}
