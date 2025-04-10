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

// Query is the registry query interface.
type Query interface {
	Entity(context.Context, signature.PublicKey) (*entity.Entity, error)
	Entities(context.Context) ([]*entity.Entity, error)
	Node(context.Context, signature.PublicKey) (*node.Node, error)
	NodeByConsensusAddress(context.Context, []byte) (*node.Node, error)
	NodeStatus(context.Context, signature.PublicKey) (*registry.NodeStatus, error)
	Nodes(context.Context) ([]*node.Node, error)
	Runtime(ctx context.Context, id common.Namespace, includeSuspended bool) (*registry.Runtime, error)
	Runtimes(ctx context.Context, includeSuspended bool) ([]*registry.Runtime, error)
	Genesis(context.Context) (*registry.Genesis, error)
	ConsensusParameters(context.Context) (*registry.ConsensusParameters, error)
}

// QueryFactory is the registry query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the registry query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &registryQuerier{
		queryState: f.state,
		state:      registryState.NewImmutableState(state),
		height:     height,
	}, nil
}

type registryQuerier struct {
	queryState abciAPI.ApplicationQueryState
	state      *registryState.ImmutableState
	height     int64
}

func (q *registryQuerier) Entity(ctx context.Context, id signature.PublicKey) (*entity.Entity, error) {
	return q.state.Entity(ctx, id)
}

func (q *registryQuerier) Entities(ctx context.Context) ([]*entity.Entity, error) {
	return q.state.Entities(ctx)
}

func (q *registryQuerier) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
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

func (q *registryQuerier) NodeByConsensusAddress(ctx context.Context, address []byte) (*node.Node, error) {
	return q.state.NodeByConsensusAddress(ctx, address)
}

func (q *registryQuerier) NodeStatus(ctx context.Context, id signature.PublicKey) (*registry.NodeStatus, error) {
	return q.state.NodeStatus(ctx, id)
}

func (q *registryQuerier) Nodes(ctx context.Context) ([]*node.Node, error) {
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

func (q *registryQuerier) Runtime(ctx context.Context, id common.Namespace, includeSuspended bool) (*registry.Runtime, error) {
	if includeSuspended {
		return q.state.AnyRuntime(ctx, id)
	}
	return q.state.Runtime(ctx, id)
}

func (q *registryQuerier) Runtimes(ctx context.Context, includeSuspended bool) ([]*registry.Runtime, error) {
	if includeSuspended {
		return q.state.AllRuntimes(ctx)
	}
	return q.state.Runtimes(ctx)
}

func (q *registryQuerier) ConsensusParameters(ctx context.Context) (*registry.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
