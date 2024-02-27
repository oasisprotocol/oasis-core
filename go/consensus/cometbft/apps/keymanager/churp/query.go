package churp

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// Query is the key manager CHURP query interface.
type Query interface {
	ConsensusParameters(context.Context) (*churp.ConsensusParameters, error)
	Status(context.Context, common.Namespace, uint8) (*churp.Status, error)
	Statuses(context.Context, common.Namespace) ([]*churp.Status, error)
	AllStatuses(context.Context) ([]*churp.Status, error)
}

type querier struct {
	state *churpState.ImmutableState
}

// ConsensusParameters implements Query.
func (q *querier) ConsensusParameters(ctx context.Context) (*churp.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// Status implements Query.
func (q *querier) Status(ctx context.Context, runtimeID common.Namespace, churpID uint8) (*churp.Status, error) {
	return q.state.Status(ctx, runtimeID, churpID)
}

// Statuses implements Query.
func (q *querier) Statuses(ctx context.Context, runtimeID common.Namespace) ([]*churp.Status, error) {
	return q.state.Statuses(ctx, runtimeID)
}

// AllStatuses implements Query.
func (q *querier) AllStatuses(ctx context.Context) ([]*churp.Status, error) {
	return q.state.AllStatuses(ctx)
}

// NewQuery creates a new key manager CHURP query.
func NewQuery(state *churpState.ImmutableState) Query {
	return &querier{state}
}
