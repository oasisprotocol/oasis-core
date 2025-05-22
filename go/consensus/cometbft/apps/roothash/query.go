package roothash

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is the roothash query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new roothash query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a roothash query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	tree, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	state := roothashState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// LightQueryFactory is the roothash light query factory.
type LightQueryFactory struct {
	rooter abciAPI.StateRooter
	syncer syncer.ReadSyncer
}

// NewLightQueryFactory returns a new roothash query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) *LightQueryFactory {
	return &LightQueryFactory{
		rooter: rooter,
		syncer: syncer,
	}
}

// QueryAt returns a roothash query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	root, err := f.rooter.StateRoot(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to get state root: %w", err)
	}
	tree := mkvs.NewWithRoot(f.syncer, nil, root)
	state := roothashState.NewImmutableState(tree)
	query := NewQuery(state)
	return query, nil
}

// Query is the roothash query.
type Query struct {
	state *roothashState.ImmutableState
}

// NewQuery returns a new roothash query backed by the given state.
func NewQuery(state *roothashState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// GenesisBlock implements roothash.Query.
func (q *Query) GenesisBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := q.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.GenesisBlock, nil
}

// LatestBlock implements roothash.Query.
func (q *Query) LatestBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := q.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.LastBlock, nil
}

// RuntimeState implements roothash.Query.
func (q *Query) RuntimeState(ctx context.Context, id common.Namespace) (*roothash.RuntimeState, error) {
	return q.state.RuntimeState(ctx, id)
}

// RoundRoots implements roothash.Query.
func (q *Query) RoundRoots(ctx context.Context, id common.Namespace, round uint64) (*roothash.RoundRoots, error) {
	return q.state.RoundRoots(ctx, id, round)
}

// PastRoundRoots implements roothash.Query.
func (q *Query) PastRoundRoots(ctx context.Context, id common.Namespace) (map[uint64]roothash.RoundRoots, error) {
	return q.state.PastRoundRoots(ctx, id)
}

// LastRoundResults implements roothash.Query.
func (q *Query) LastRoundResults(ctx context.Context, id common.Namespace) (*roothash.RoundResults, error) {
	return q.state.LastRoundResults(ctx, id)
}

// IncomingMessageQueueMeta implements roothash.Query.
func (q *Query) IncomingMessageQueueMeta(ctx context.Context, id common.Namespace) (*message.IncomingMessageQueueMeta, error) {
	return q.state.IncomingMessageQueueMeta(ctx, id)
}

// IncomingMessageQueue implements roothash.Query.
func (q *Query) IncomingMessageQueue(ctx context.Context, id common.Namespace, offset uint64, limit uint32) ([]*message.IncomingMessage, error) {
	return q.state.IncomingMessageQueue(ctx, id, offset, limit)
}

// ConsensusParameters implements roothash.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*roothash.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}
