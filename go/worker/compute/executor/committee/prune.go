package committee

import (
	"context"
	"fmt"

	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// pruneHandler is a prune handler that prevents pruning of the last successful round.
type pruneHandler struct {
	commonNode *committee.Node
}

func (p *pruneHandler) Prune(ctx context.Context, rounds []uint64) error {
	p.commonNode.CrossNode.Lock()
	height := p.commonNode.CurrentBlockHeight
	p.commonNode.CrossNode.Unlock()

	// Make sure we never prune past the last successful round as we need that round in history so
	// we can fetch any needed round results.
	state, err := p.commonNode.Consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: p.commonNode.Runtime.ID(),
		Height:    height,
	})
	if err != nil {
		return fmt.Errorf("worker/executor: failed to fetch runtime state at %d: %w", height, err)
	}

	for _, round := range rounds {
		if round >= state.LastNormalRound {
			return fmt.Errorf("worker/executor: tried to prune past last normal round (%d)", state.LastNormalRound)
		}
	}
	return nil
}
