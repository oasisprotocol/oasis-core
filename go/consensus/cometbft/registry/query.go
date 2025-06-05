package registry

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is a registry query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a registry query implementation.
type Query interface {
	// Entity looks up a registered entity by its identifier.
	Entity(context.Context, signature.PublicKey) (*entity.Entity, error)
	// Entities returns a list of all registered entities.
	Entities(context.Context) ([]*entity.Entity, error)
	// Node looks up a specific node by its identifier.
	Node(context.Context, signature.PublicKey) (*node.Node, error)
	// NodeByConsensusAddress looks up a specific node by its consensus address.
	NodeByConsensusAddress(context.Context, []byte) (*node.Node, error)
	// NodeStatus returns a specific node status.
	NodeStatus(context.Context, signature.PublicKey) (*registry.NodeStatus, error)
	// Nodes returns a list of all registered nodes.
	Nodes(context.Context) ([]*node.Node, error)
	// Runtime looks up a runtime by its identifier and returns it.
	Runtime(ctx context.Context, id common.Namespace, includeSuspended bool) (*registry.Runtime, error)
	// Runtimes returns a list of all registered runtimes.
	Runtimes(ctx context.Context, includeSuspended bool) ([]*registry.Runtime, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*registry.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*registry.ConsensusParameters, error)
}

// StateQueryFactory is a registry state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new registry query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a registry query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}

// LightQueryFactory is a registry light query factory.
type LightQueryFactory struct {
	querier *app.LightQueryFactory
}

// NewLightQueryFactory returns a new registry query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) QueryFactory {
	return &LightQueryFactory{
		querier: app.NewLightQueryFactory(rooter, syncer),
	}
}

// QueryAt returns a registry query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
