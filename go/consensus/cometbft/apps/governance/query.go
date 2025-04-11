package governance

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// QueryFactory is the governance query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new governance query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a governance query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return NewQuery(governanceState.NewImmutableState(state)), nil
}

// Query is the governance query.
type Query struct {
	state *governanceState.ImmutableState
}

// NewQuery returns a new governance query backed by the given state.
func NewQuery(state *governanceState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// ActiveProposals implements governance.Query.
func (q *Query) ActiveProposals(ctx context.Context) ([]*governance.Proposal, error) {
	return q.state.ActiveProposals(ctx)
}

// Proposals implements governance.Query.
func (q *Query) Proposals(ctx context.Context) ([]*governance.Proposal, error) {
	return q.state.Proposals(ctx)
}

// Proposal implements governance.Query.
func (q *Query) Proposal(ctx context.Context, id uint64) (*governance.Proposal, error) {
	return q.state.Proposal(ctx, id)
}

// Votes implements governance.Query.
func (q *Query) Votes(ctx context.Context, id uint64) ([]*governance.VoteEntry, error) {
	return q.state.Votes(ctx, id)
}

// PendingUpgrades implements governance.Query.
func (q *Query) PendingUpgrades(ctx context.Context) ([]*upgrade.Descriptor, error) {
	return q.state.PendingUpgrades(ctx)
}

// ConsensusParameters implements governance.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*governance.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
