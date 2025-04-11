package scheduler

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Query is the scheduler query interface.
type Query interface {
	Validators(context.Context) ([]*scheduler.Validator, error)
	AllCommittees(context.Context) ([]*scheduler.Committee, error)
	KindsCommittees(context.Context, []scheduler.CommitteeKind) ([]*scheduler.Committee, error)
	Genesis(context.Context) (*scheduler.Genesis, error)
	ConsensusParameters(context.Context) (*scheduler.ConsensusParameters, error)
}

// QueryFactory is the scheduler query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the scheduler query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &schedulerQuerier{
		state: schedulerState.NewImmutableState(state),
	}, nil
}

type schedulerQuerier struct {
	state *schedulerState.ImmutableState
}

func (q *schedulerQuerier) Validators(ctx context.Context) ([]*scheduler.Validator, error) {
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

func (q *schedulerQuerier) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return q.state.AllCommittees(ctx)
}

func (q *schedulerQuerier) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return q.state.KindsCommittees(ctx, kinds)
}

func (q *schedulerQuerier) ConsensusParameters(ctx context.Context) (*scheduler.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
