package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
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
	state, err := keymanagerState.NewImmutableState(ctx, sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &keymanagerQuerier{state}, nil
}

type keymanagerQuerier struct {
	state *keymanagerState.ImmutableState
}

func (kq *keymanagerQuerier) Status(ctx context.Context, id common.Namespace) (*keymanager.Status, error) {
	return kq.state.Status(ctx, id)
}

func (kq *keymanagerQuerier) Statuses(ctx context.Context) ([]*keymanager.Status, error) {
	return kq.state.Statuses(ctx)
}

func (app *keymanagerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
