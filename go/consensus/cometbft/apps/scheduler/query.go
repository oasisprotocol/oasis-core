package scheduler

import (
	"context"
	"fmt"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is the scheduler query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new scheduler query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}

// QueryAt returns a scheduler query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	tree, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	state := schedulerState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// LightQueryFactory is the scheduler light query factory.
type LightQueryFactory struct {
	rooter abciAPI.StateRooter
	syncer syncer.ReadSyncer
}

// NewLightQueryFactory returns a new scheduler query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) *LightQueryFactory {
	return &LightQueryFactory{
		rooter: rooter,
		syncer: syncer,
	}
}

// QueryAt returns a scheduler query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	root, err := f.rooter.StateRoot(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to get state root: %w", err)
	}
	tree := mkvs.NewWithRoot(f.syncer, nil, root)
	state := schedulerState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

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
