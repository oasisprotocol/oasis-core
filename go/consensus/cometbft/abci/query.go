package abci

import (
	"context"

	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci/state"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

// Query is the consensus backend query interface.
type Query interface {
	ChainContext(ctx context.Context) (string, error)
	ConsensusParameters(ctx context.Context) (*consensusGenesis.Parameters, error)
}

// QueryFactory is the consensus backend query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}

// QueryAt returns the consensus backend query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &consensusQuerier{
		state: consensusState.NewImmutableState(state),
	}, nil
}

type consensusQuerier struct {
	state *consensusState.ImmutableState
}

func (q *consensusQuerier) ChainContext(ctx context.Context) (string, error) {
	return q.state.ChainContext(ctx)
}

func (q *consensusQuerier) ConsensusParameters(ctx context.Context) (*consensusGenesis.Parameters, error) {
	return q.state.ConsensusParameters(ctx)
}
