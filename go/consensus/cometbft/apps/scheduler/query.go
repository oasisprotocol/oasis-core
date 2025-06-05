package scheduler

import (
	"context"

	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Query is the scheduler query.
type Query struct {
	state *schedulerState.ImmutableState
}

// NewQuery returns a new scheduler query backed by the given state.
func NewQuery(state *schedulerState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// Validators implements scheduler.Query.
func (q *Query) Validators(ctx context.Context) ([]*scheduler.Validator, error) {
	vals, err := q.state.CurrentValidators(ctx)
	if err != nil {
		return nil, err
	}

	ret := make([]*scheduler.Validator, 0, len(vals))
	for _, v := range vals {
		ret = append(ret, v)
	}

	return ret, nil
}

// AllCommittees implements scheduler.Query.
func (q *Query) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return q.state.AllCommittees(ctx)
}

// KindsCommittees implements scheduler.Query.
func (q *Query) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return q.state.KindsCommittees(ctx, kinds)
}

// ConsensusParameters implements scheduler.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*scheduler.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
