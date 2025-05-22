package consensus

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

// QueryFactory is the consensus query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new consensus query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a consensus query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	tree, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	state := consensusState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

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
