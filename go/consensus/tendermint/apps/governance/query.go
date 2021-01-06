package governance

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
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
func (qf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := governanceState.NewImmutableState(ctx, qf.state, height)
	if err != nil {
		return nil, err
	}
	return &governanceQuerier{state}, nil
}

type governanceQuerier struct {
	state *governanceState.ImmutableState
}

func (gq *governanceQuerier) ActiveProposals(ctx context.Context) ([]*governance.Proposal, error) {
	return gq.state.ActiveProposals(ctx)
}

func (gq *governanceQuerier) Proposals(ctx context.Context) ([]*governance.Proposal, error) {
	return gq.state.Proposals(ctx)
}

func (gq *governanceQuerier) Proposal(ctx context.Context, id uint64) (*governance.Proposal, error) {
	return gq.state.Proposal(ctx, id)
}

func (gq *governanceQuerier) Votes(ctx context.Context, id uint64) ([]*governance.VoteEntry, error) {
	return gq.state.Votes(ctx, id)
}

func (gq *governanceQuerier) PendingUpgrades(ctx context.Context) ([]*upgrade.Descriptor, error) {
	return gq.state.PendingUpgrades(ctx)
}

func (gq *governanceQuerier) ConsensusParameters(ctx context.Context) (*governance.ConsensusParameters, error) {
	return gq.state.ConsensusParameters(ctx)
}

func (app *governanceApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
