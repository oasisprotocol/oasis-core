package registry

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// QueryFactory is the registry query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new registry query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a registry query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return NewQuery(height, f.state, registryState.NewImmutableState(state)), nil
}

// Query is the registry query.
type Query struct {
	height     int64
	queryState abciAPI.ApplicationQueryState
	state      *registryState.ImmutableState
}

// NewQuery returns a new registry query backed by the given state.
func NewQuery(height int64, queryState abciAPI.ApplicationQueryState, state *registryState.ImmutableState) *Query {
	return &Query{
		height:     height,
		queryState: queryState,
		state:      state,
	}
}

// Entity implements registry.Query.
func (q *Query) Entity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	return q.state.Entity(ctx, id)
}

// Entities implements registry.Query.
func (q *Query) Entities(ctx context.Context) ([]*entity.Entity, error) {
	return q.state.Entities(ctx)
}

// Node implements registry.Query.
func (q *Query) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	epoch, err := q.queryState.GetEpoch(ctx, q.height)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch: %w", err)
	}

	node, err := q.state.Node(ctx, id)
	if err != nil {
		return nil, err
	}

	// Do not return expired nodes.
	if node.IsExpired(uint64(epoch)) {
		return nil, registry.ErrNoSuchNode
	}
	return node, nil
}

// NodeByConsensusAddress implements registry.Query.
func (q *Query) NodeByConsensusAddress(ctx context.Context, address []byte) (*node.Node, error) {
	return q.state.NodeByConsensusAddress(ctx, address)
}

// NodeStatus implements registry.Query.
func (q *Query) NodeStatus(ctx context.Context, id signature.PublicKey) (*registry.NodeStatus, error) {
	return q.state.NodeStatus(ctx, id)
}

// Nodes implements registry.Query.
func (q *Query) Nodes(ctx context.Context) ([]*node.Node, error) {
	epoch, err := q.queryState.GetEpoch(ctx, q.height)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch: %w", err)
	}

	nodes, err := q.state.Nodes(ctx)
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

// Runtime implements registry.Query.
func (q *Query) Runtime(ctx context.Context, id common.Namespace, includeSuspended bool) (*registry.Runtime, error) {
	if includeSuspended {
		return q.state.AnyRuntime(ctx, id)
	}
	return q.state.Runtime(ctx, id)
}

// Runtimes implements registry.Query.
func (q *Query) Runtimes(ctx context.Context, includeSuspended bool) ([]*registry.Runtime, error) {
	if includeSuspended {
		return q.state.AllRuntimes(ctx)
	}
	return q.state.Runtimes(ctx)
}

// ConsensusParameters implements registry.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*registry.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
