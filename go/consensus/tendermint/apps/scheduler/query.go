package scheduler

import (
	"context"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	schedulerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

// Query is the scheduler query interface.
type Query interface {
	Validators(context.Context) ([]*scheduler.Validator, error)
	AllCommittees(context.Context) ([]*scheduler.Committee, error)
	KindsCommittees(context.Context, []scheduler.CommitteeKind) ([]*scheduler.Committee, error)
	Genesis(context.Context) (*scheduler.Genesis, error)
}

// QueryFactory is the scheduler query factory.
type QueryFactory struct {
	app *schedulerApplication
}

// QueryAt returns the scheduler query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	var state *schedulerState.ImmutableState
	var err error
	abciCtx := abci.FromCtx(ctx)

	// If this request was made from InitChain, no blocks and states have been
	// submitted yet, so we use the existing state instead.
	if abciCtx != nil && abciCtx.IsInitChain() {
		state = schedulerState.NewMutableState(abciCtx.State()).ImmutableState
	} else {
		state, err = schedulerState.NewImmutableState(sf.app.state, height)
		if err != nil {
			return nil, err
		}
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}

	return &schedulerQuerier{state}, nil
}

type schedulerQuerier struct {
	state *schedulerState.ImmutableState
}

func (sq *schedulerQuerier) Validators(ctx context.Context) ([]*scheduler.Validator, error) {
	valPks, err := sq.state.CurrentValidators()
	if err != nil {
		return nil, err
	}

	// Since we use flat voting power for now, doing it this way saves
	// having to store consensus.VotingPower repeatedly in the validator set
	// ABCI state.
	ret := make([]*scheduler.Validator, 0, len(valPks))
	for _, v := range valPks {
		ret = append(ret, &scheduler.Validator{
			ID:          v,
			VotingPower: consensus.VotingPower,
		})
	}

	return ret, nil
}

func (sq *schedulerQuerier) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return sq.state.AllCommittees()
}

func (sq *schedulerQuerier) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return sq.state.KindsCommittees(kinds)
}

func (app *schedulerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
