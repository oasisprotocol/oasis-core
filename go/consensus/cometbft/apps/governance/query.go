package governance

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// Query is the governance query interface.
type Query interface {
	ActiveProposals(context.Context) ([]*governance.Proposal, error)
	Proposals(context.Context) ([]*governance.Proposal, error)
	Proposal(context.Context, uint64) (*governance.Proposal, error)
	Votes(context.Context, uint64) ([]*governance.VoteEntry, error)
	PendingUpgrades(context.Context) ([]*upgrade.Descriptor, error)
	Genesis(context.Context) (*governance.Genesis, error)
	ConsensusParameters(context.Context) (*governance.ConsensusParameters, error)
}

// QueryFactory is the governance query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the governance query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &governanceQuerier{
		state: governanceState.NewImmutableState(state),
	}, nil
}

type governanceQuerier struct {
	state *governanceState.ImmutableState
}

func (q *governanceQuerier) ActiveProposals(ctx context.Context) ([]*governance.Proposal, error) {
	return q.state.ActiveProposals(ctx)
}

func (q *governanceQuerier) Proposals(ctx context.Context) ([]*governance.Proposal, error) {
	return q.state.Proposals(ctx)
}

func (q *governanceQuerier) Proposal(ctx context.Context, id uint64) (*governance.Proposal, error) {
	return q.state.Proposal(ctx, id)
}

func (q *governanceQuerier) Votes(ctx context.Context, id uint64) ([]*governance.VoteEntry, error) {
	return q.state.Votes(ctx, id)
}

func (q *governanceQuerier) PendingUpgrades(ctx context.Context) ([]*upgrade.Descriptor, error) {
	return q.state.PendingUpgrades(ctx)
}

func (q *governanceQuerier) ConsensusParameters(ctx context.Context) (*governance.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

func (app *governanceApplication) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
