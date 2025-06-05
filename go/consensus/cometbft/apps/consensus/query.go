package consensus

import (
	"context"

	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

// Query is the consensus query.
type Query struct {
	state *consensusState.ImmutableState
}

// NewQuery returns a new consensus query backed by the given state.
func NewQuery(state *consensusState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// ChainContext implements consensus.Query.
func (q *Query) ChainContext(ctx context.Context) (string, error) {
	return q.state.ChainContext(ctx)
}

// ConsensusParameters implements consensus.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*consensusGenesis.Parameters, error) {
	return q.state.ConsensusParameters(ctx)
}
