package churp

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// Query is the key manager query interface.
type Query interface {
	Status(context.Context, common.Namespace, uint8) (*churp.Status, error)
	Statuses(context.Context, common.Namespace) ([]*churp.Status, error)
	AllStatuses(context.Context) ([]*churp.Status, error)
}

type querier struct {
	state *churpState.ImmutableState
}

func (kq *querier) Status(ctx context.Context, runtimeID common.Namespace, churpID uint8) (*churp.Status, error) {
	return kq.state.Status(ctx, runtimeID, churpID)
}

func (kq *querier) Statuses(ctx context.Context, runtimeID common.Namespace) ([]*churp.Status, error) {
	return kq.state.Statuses(ctx, runtimeID)
}

func (kq *querier) AllStatuses(ctx context.Context) ([]*churp.Status, error) {
	return kq.state.AllStatuses(ctx)
}

func NewQuery(state *churpState.ImmutableState) Query {
	return &querier{state}
}
