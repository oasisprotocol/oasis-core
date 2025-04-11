package churp

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// QueryFactory is a key manager CHURP query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a key manager CHURP query implementation.
type Query interface {
	// Status returns status for the given runtime.
	Status(context.Context, common.Namespace, uint8) (*churp.Status, error)
	// Statuses returns all statuses for the given runtime.
	Statuses(context.Context, common.Namespace) ([]*churp.Status, error)
	// Statuses returns all statuses.
	AllStatuses(context.Context) ([]*churp.Status, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*churp.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*churp.ConsensusParameters, error)
}

// StateQueryFactory is a key manager CHURP state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new key manager CHURP query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a key manager CHURP query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
