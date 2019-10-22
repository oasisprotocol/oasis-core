package registry

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// Query is the registry query interface.
type Query interface {
	Entity(context.Context, signature.PublicKey) (*entity.Entity, error)
	Entities(context.Context) ([]*entity.Entity, error)
	Node(context.Context, signature.PublicKey) (*node.Node, error)
	Nodes(context.Context) ([]*node.Node, error)
	Runtime(context.Context, signature.PublicKey) (*registry.Runtime, error)
	Runtimes(context.Context) ([]*registry.Runtime, error)
	Genesis(context.Context) (*registry.Genesis, error)
}

// QueryFactory is the registry query factory.
type QueryFactory struct {
	app *registryApplication
}

// QueryAt returns the registry query interface for a specific height.
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &registryQuerier{state}, nil
}

type registryQuerier struct {
	state *immutableState
}

func (rq *registryQuerier) Entity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	return rq.state.getEntity(id)
}

func (rq *registryQuerier) Entities(ctx context.Context) ([]*entity.Entity, error) {
	return rq.state.getEntities()
}

func (rq *registryQuerier) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	return rq.state.GetNode(id)
}

func (rq *registryQuerier) Nodes(ctx context.Context) ([]*node.Node, error) {
	return rq.state.GetNodes()
}

func (rq *registryQuerier) Runtime(ctx context.Context, id signature.PublicKey) (*registry.Runtime, error) {
	return rq.state.GetRuntime(id)
}

func (rq *registryQuerier) Runtimes(ctx context.Context) ([]*registry.Runtime, error) {
	return rq.state.GetRuntimes()
}

func (app *registryApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
