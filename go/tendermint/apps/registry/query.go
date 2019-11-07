package registry

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/tendermint/apps/registry/state"
)

// Query is the registry query interface.
type Query interface {
	Entity(context.Context, signature.PublicKey) (*entity.Entity, error)
	Entities(context.Context) ([]*entity.Entity, error)
	Node(context.Context, signature.PublicKey) (*node.Node, error)
	NodeStatus(context.Context, signature.PublicKey) (*registry.NodeStatus, error)
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
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := registryState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx := abci.FromCtx(ctx); abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}
	return &registryQuerier{sf.app, state, height}, nil
}

type registryQuerier struct {
	app    *registryApplication
	state  *registryState.ImmutableState
	height int64
}

func (rq *registryQuerier) Entity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	return rq.state.Entity(id)
}

func (rq *registryQuerier) Entities(ctx context.Context) ([]*entity.Entity, error) {
	return rq.state.Entities()
}

func (rq *registryQuerier) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	epoch, err := rq.app.state.GetEpoch(ctx, rq.height)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch: %w", err)
	}

	node, err := rq.state.Node(id)
	if err != nil {
		return nil, err
	}

	// Do not return expired nodes.
	if node.IsExpired(uint64(epoch)) {
		return nil, registry.ErrNoSuchNode
	}
	return node, nil
}

func (rq *registryQuerier) NodeStatus(ctx context.Context, id signature.PublicKey) (*registry.NodeStatus, error) {
	return rq.state.NodeStatus(id)
}

func (rq *registryQuerier) Nodes(ctx context.Context) ([]*node.Node, error) {
	epoch, err := rq.app.state.GetEpoch(ctx, rq.height)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch: %w", err)
	}

	nodes, err := rq.state.Nodes()
	if err != nil {
		return nil, err
	}

	// Filter out expired nodes.
	var filteredNodes []*node.Node
	for _, n := range nodes {
		if n.IsExpired(uint64(epoch)) {
			continue
		}
		filteredNodes = append(filteredNodes, n)
	}
	return filteredNodes, nil
}

func (rq *registryQuerier) Runtime(ctx context.Context, id signature.PublicKey) (*registry.Runtime, error) {
	return rq.state.Runtime(id)
}

func (rq *registryQuerier) Runtimes(ctx context.Context) ([]*registry.Runtime, error) {
	return rq.state.Runtimes()
}

func (app *registryApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
