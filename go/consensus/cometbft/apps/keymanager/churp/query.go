package churp

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is the key manager CHURP query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new key manager CHURP query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a key manager CHURP query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	tree, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	state := churpState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// LightQueryFactory is the key manager CHURP light query factory.
type LightQueryFactory struct {
	rooter abciAPI.StateRooter
	syncer syncer.ReadSyncer
}

// NewLightQueryFactory returns a new key manager CHURP query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) *LightQueryFactory {
	return &LightQueryFactory{
		rooter: rooter,
		syncer: syncer,
	}
}

// QueryAt returns a key manager CHURP query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	root, err := f.rooter.StateRoot(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to get state root: %w", err)
	}
	tree := mkvs.NewWithRoot(f.syncer, nil, root)
	state := churpState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// Query is the key manager CHURP query.
type Query struct {
	state *churpState.ImmutableState
}

// NewQuery creates a new key manager CHURP query.
func NewQuery(state *churpState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// ConsensusParameters implements churp.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*churp.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// Status implements churp.Query.
func (q *Query) Status(ctx context.Context, runtimeID common.Namespace, churpID uint8) (*churp.Status, error) {
	return q.state.Status(ctx, runtimeID, churpID)
}

// Statuses implements churp.Query.
func (q *Query) Statuses(ctx context.Context, runtimeID common.Namespace) ([]*churp.Status, error) {
	return q.state.Statuses(ctx, runtimeID)
}

// AllStatuses implements churp.Query.
func (q *Query) AllStatuses(ctx context.Context) ([]*churp.Status, error) {
	return q.state.AllStatuses(ctx)
}
