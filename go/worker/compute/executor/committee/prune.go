package committee

import (
	"context"
	"fmt"

	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

// pruneHandler is a prune handler that prevents pruning of the last normal round.
type pruneHandler struct {
	commonNode *committee.Node
}

func (p *pruneHandler) Prune(rounds []uint64) error {
	p.commonNode.CrossNode.Lock()
	height := p.commonNode.CurrentBlockHeight
	p.commonNode.CrossNode.Unlock()

	// Make sure we never prune past the last normal round, as some runtimes will do historic queries
	// for things that are not available in the last consensus state (e.g. delegation/undelegation
	// events that happened while the runtime was suspended or not producing blocks).
	state, err := p.commonNode.Consensus.RootHash().GetRuntimeState(context.Background(), &roothash.RuntimeRequest{
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
