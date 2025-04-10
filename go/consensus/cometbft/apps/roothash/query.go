package roothash

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

// Query is the roothash query interface.
type Query interface {
	LatestBlock(context.Context, common.Namespace) (*block.Block, error)
	GenesisBlock(context.Context, common.Namespace) (*block.Block, error)
	RuntimeState(context.Context, common.Namespace) (*roothash.RuntimeState, error)
	LastRoundResults(context.Context, common.Namespace) (*roothash.RoundResults, error)
	RoundRoots(context.Context, common.Namespace, uint64) (*roothash.RoundRoots, error)
	PastRoundRoots(context.Context, common.Namespace) (map[uint64]roothash.RoundRoots, error)
	IncomingMessageQueueMeta(context.Context, common.Namespace) (*message.IncomingMessageQueueMeta, error)
	IncomingMessageQueue(ctx context.Context, id common.Namespace, offset uint64, limit uint32) ([]*message.IncomingMessage, error)
	Genesis(context.Context) (*roothash.Genesis, error)
	ConsensusParameters(context.Context) (*roothash.ConsensusParameters, error)
}

// QueryFactory is the roothash query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the roothash query interface for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &rootHashQuerier{
		state: roothashState.NewImmutableState(state),
	}, nil
}

type rootHashQuerier struct {
	state *roothashState.ImmutableState
}

func (q *rootHashQuerier) LatestBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := q.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.LastBlock, nil
}

func (q *rootHashQuerier) GenesisBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := q.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.GenesisBlock, nil
}

func (q *rootHashQuerier) RuntimeState(ctx context.Context, id common.Namespace) (*roothash.RuntimeState, error) {
	return q.state.RuntimeState(ctx, id)
}

func (q *rootHashQuerier) LastRoundResults(ctx context.Context, id common.Namespace) (*roothash.RoundResults, error) {
	return q.state.LastRoundResults(ctx, id)
}

func (q *rootHashQuerier) RoundRoots(ctx context.Context, id common.Namespace, round uint64) (*roothash.RoundRoots, error) {
	return q.state.RoundRoots(ctx, id, round)
}

func (q *rootHashQuerier) PastRoundRoots(ctx context.Context, id common.Namespace) (map[uint64]roothash.RoundRoots, error) {
	return q.state.PastRoundRoots(ctx, id)
}

func (q *rootHashQuerier) IncomingMessageQueueMeta(ctx context.Context, id common.Namespace) (*message.IncomingMessageQueueMeta, error) {
	return q.state.IncomingMessageQueueMeta(ctx, id)
}

func (q *rootHashQuerier) IncomingMessageQueue(ctx context.Context, id common.Namespace, offset uint64, limit uint32) ([]*message.IncomingMessage, error) {
	return q.state.IncomingMessageQueue(ctx, id, offset, limit)
}

func (q *rootHashQuerier) ConsensusParameters(ctx context.Context) (*roothash.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

func (app *Application) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
