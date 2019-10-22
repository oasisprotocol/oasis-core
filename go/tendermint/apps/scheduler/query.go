package scheduler

import (
	"context"

	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

// Query is the scheduler query interface.
type Query interface {
	AllCommittees(context.Context) ([]*scheduler.Committee, error)
	KindsCommittees(context.Context, []scheduler.CommitteeKind) ([]*scheduler.Committee, error)
}

// QueryFactory is the scheduler query factory.
type QueryFactory struct {
	app *schedulerApplication
}

// QueryAt returns the scheduler query interface for a specific height.
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &schedulerQuerier{state}, nil
}

type schedulerQuerier struct {
	state *immutableState
}

func (sq *schedulerQuerier) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return sq.state.getAllCommittees()
}

func (sq *schedulerQuerier) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return sq.state.getKindsCommittees(kinds)
}

func (app *schedulerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
