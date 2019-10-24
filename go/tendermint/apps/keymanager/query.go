package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanagerState "github.com/oasislabs/oasis-core/go/tendermint/apps/keymanager/state"
)

// Query is the key manager query interface.
type Query interface {
	Status(context.Context, signature.PublicKey) (*keymanager.Status, error)
	Statuses(context.Context) ([]*keymanager.Status, error)
	Genesis(context.Context) (*keymanager.Genesis, error)
}

// QueryFactory is the key manager query factory.
type QueryFactory struct {
	app *keymanagerApplication
}

// QueryAt returns the key manager query interface for a specific height.
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := keymanagerState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &keymanagerQuerier{state}, nil
}

type keymanagerQuerier struct {
	state *keymanagerState.ImmutableState
}

func (kq *keymanagerQuerier) Status(ctx context.Context, id signature.PublicKey) (*keymanager.Status, error) {
	return kq.state.Status(id)
}

func (kq *keymanagerQuerier) Statuses(ctx context.Context) ([]*keymanager.Status, error) {
	return kq.state.Statuses()
}

func (app *keymanagerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
