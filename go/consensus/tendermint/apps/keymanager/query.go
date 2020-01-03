package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	keymanagerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
)

// Query is the key manager query interface.
type Query interface {
	Status(context.Context, common.Namespace) (*keymanager.Status, error)
	Statuses(context.Context) ([]*keymanager.Status, error)
	Genesis(context.Context) (*keymanager.Genesis, error)
}

// QueryFactory is the key manager query factory.
type QueryFactory struct {
	app *keymanagerApplication
}

// QueryAt returns the key manager query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	var state *keymanagerState.ImmutableState
	var err error
	abciCtx := abci.FromCtx(ctx)

	// If this request was made from InitChain, no blocks and states have been
	// submitted yet, so we use the existing state instead.
	if abciCtx != nil && abciCtx.IsInitChain() {
		state = keymanagerState.NewMutableState(abciCtx.State()).ImmutableState
	} else {
		state, err = keymanagerState.NewImmutableState(sf.app.state, height)
		if err != nil {
			return nil, err
		}
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}

	return &keymanagerQuerier{state}, nil
}

type keymanagerQuerier struct {
	state *keymanagerState.ImmutableState
}

func (kq *keymanagerQuerier) Status(ctx context.Context, id common.Namespace) (*keymanager.Status, error) {
	return kq.state.Status(id)
}

func (kq *keymanagerQuerier) Statuses(ctx context.Context) ([]*keymanager.Status, error) {
	return kq.state.Statuses()
}

func (app *keymanagerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
