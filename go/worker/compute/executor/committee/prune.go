package committee

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// PruneHandler is a prune handler that prevents pruning of the last normal round.
type PruneHandler struct {
	runtimeID common.Namespace
	consensus consensus.Service
}

// NewPruneHandler creates a new prune handler.
func NewPruneHandler(runtimeID common.Namespace, consensus consensus.Service) *PruneHandler {
	return &PruneHandler{
		runtimeID: runtimeID,
		consensus: consensus,
	}
}

// CanPruneRuntime returns no error when pruning runtime rounds would not go past last normal round.
//
// This is important as some runtimes will do historic queries for things that are not available
// in the last consensus state (e.g. delegation/undelegation events that happened while the runtime
// was suspended or not producing blocks).
//
// Implements runtime.history.PruneHandler.
func (p *PruneHandler) CanPruneRuntime(rounds []uint64) error {
	state, err := p.consensus.RootHash().GetRuntimeState(context.TODO(), &roothash.RuntimeRequest{
		RuntimeID: p.runtimeID,
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		return fmt.Errorf("worker/executor: failed to fetch runtime state: %w", err)
	}

	for _, round := range rounds {
		if round >= state.LastNormalRound {
			return fmt.Errorf("worker/executor: tried to prune past last normal round (%d)", state.LastNormalRound)
		}
	}
	return nil
}
