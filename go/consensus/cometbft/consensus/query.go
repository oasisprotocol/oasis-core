package consensus

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

// QueryFactory is a consensus query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a consensus query implementation.
type Query interface {
	// ChainContext returns chain context.
	ChainContext(context.Context) (string, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*consensusGenesis.Parameters, error)
}

// StateQueryFactory is a consensus state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new consensus query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a consensus query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
