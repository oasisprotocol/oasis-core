package keymanager

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
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
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &keymanagerQuerier{state}, nil
}

type keymanagerQuerier struct {
	state *immutableState
}

func (kq *keymanagerQuerier) Status(ctx context.Context, id signature.PublicKey) (*keymanager.Status, error) {
	return kq.state.GetStatus(id)
}

func (kq *keymanagerQuerier) Statuses(ctx context.Context) ([]*keymanager.Status, error) {
	return kq.state.GetStatuses()
}

func (app *keymanagerApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
