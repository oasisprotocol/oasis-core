package scheduler

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
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
	state, err := schedulerState.NewImmutableState(ctx, sf.app.state, height)
	if err != nil {
		return nil, err
	}

	// Some queries need access to the registry to give useful responses.
	regState, err := registryState.NewImmutableState(ctx, sf.app.state, height)
	if err != nil {
		return nil, err
	}

	return &schedulerQuerier{state, regState}, nil
}

type schedulerQuerier struct {
	state    *schedulerState.ImmutableState
	regState *registryState.ImmutableState
}

func (sq *schedulerQuerier) Validators(ctx context.Context) ([]*scheduler.Validator, error) {
	valPks, err := sq.state.CurrentValidators(ctx)
	if err != nil {
		return nil, err
	}

	params, err := sq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	// Since we use flat voting power for now, doing it this way saves
	// having to store consensus.VotingPower repeatedly in the validator set
	// ABCI state.
	ret := make([]*scheduler.Validator, 0, len(valPks))
	for _, v := range valPks {
		var id signature.PublicKey

		if params.DebugStaticValidators {
			// This must be unit tests.  While this call is specified to
			// return node IDs, the map for making such queries is not
			// guaranteed to be populated in the registry.
			id = v
		} else {
			// The validator list uses consensus addresses, so convert them
			// to node identifiers.
			//
			// This is probably better than switching the scheduler to use
			// node identifiers for validators, because user queries are
			// likely more infrequent than all the business of actually
			// scheduling...
			node, err := sq.regState.NodeByConsensusOrP2PKey(ctx, v)
			if err != nil {
				// Should NEVER happen.
				return nil, err
			}

			id = node.ID
		}

		ret = append(ret, &scheduler.Validator{
			ID:          id,
			VotingPower: consensus.VotingPower,
		})
	}

	return ret, nil
}

func (sq *schedulerQuerier) AllCommittees(ctx context.Context) ([]*scheduler.Committee, error) {
	return sq.state.AllCommittees(ctx)
}

func (sq *schedulerQuerier) KindsCommittees(ctx context.Context, kinds []scheduler.CommitteeKind) ([]*scheduler.Committee, error) {
	return sq.state.KindsCommittees(ctx, kinds)
}

func (app *schedulerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
