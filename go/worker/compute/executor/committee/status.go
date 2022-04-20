package committee

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
)

// GetStatus returns the executor committee node status.
func (n *Node) GetStatus(ctx context.Context) (*api.Status, error) {
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	var status api.Status
	switch {
	case !n.runtimeReady:
		status.Status = api.StatusStateWaitingRuntime
	case !n.runtimeTrustSynced:
		status.Status = api.StatusStateWaitingTrustSync
	default:
		status.Status = api.StatusStateReady
	}

	return &status, nil
}
