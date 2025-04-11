package roothash

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

// QueryFactory is a roothash query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a roothash query implementation.
type Query interface {
	// GenesisBlock returns the genesis block.
	GenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error)
	// LatestBlock returns the latest block.
	LatestBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error)
	// RuntimeState returns the given runtime's state.
	RuntimeState(ctx context.Context, runtimeID common.Namespace) (*roothash.RuntimeState, error)
	// RoundRoots returns the stored state and I/O roots for the given runtime and round.
	RoundRoots(ctx context.Context, runtimeID common.Namespace, round uint64) (*roothash.RoundRoots, error)
	// PastRoundRoots returns the stored past state and I/O roots for the given runtime.
	PastRoundRoots(ctx context.Context, runtimeID common.Namespace) (map[uint64]roothash.RoundRoots, error)
	// LastRoundResults returns the given runtime's last normal round results.
	LastRoundResults(ctx context.Context, runtimeID common.Namespace) (*roothash.RoundResults, error)
	// IncomingMessageQueueMeta returns the given runtime's incoming message queue metadata.
	IncomingMessageQueueMeta(ctx context.Context, runtimeID common.Namespace) (*message.IncomingMessageQueueMeta, error)
	// IncomingMessageQueue returns the given runtime's queued incoming messages.
	IncomingMessageQueue(ctx context.Context, runtimeID common.Namespace, offset uint64, limit uint32) ([]*message.IncomingMessage, error)
	// Genesis returns the genesis state.
	Genesis(ctx context.Context) (*roothash.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(ctx context.Context) (*roothash.ConsensusParameters, error)
}

// StateQueryFactory is a roothash state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new roothash query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a roothash query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
