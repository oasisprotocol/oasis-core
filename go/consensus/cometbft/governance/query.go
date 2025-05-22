package governance

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// QueryFactory is a governance query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a governance query implementation.
type Query interface {
	// ActiveProposals returns the currently active proposals.
	ActiveProposals(context.Context) ([]*governance.Proposal, error)
	// Proposals returns all proposals.
	Proposals(context.Context) ([]*governance.Proposal, error)
	// Proposal returns a specific proposal by its ID.
	Proposal(context.Context, uint64) (*governance.Proposal, error)
	// Votes returns all votes for a specific proposal.
	Votes(context.Context, uint64) ([]*governance.VoteEntry, error)
	// PendingUpgrades returns any pending upgrades.
	PendingUpgrades(context.Context) ([]*upgrade.Descriptor, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*governance.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*governance.ConsensusParameters, error)
}

// StateQueryFactory is a governance state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new governance query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a governance query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}

// LightQueryFactory is a governance light query factory.
type LightQueryFactory struct {
	querier *app.LightQueryFactory
}

// NewLightQueryFactory returns a new governance query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) QueryFactory {
	return &LightQueryFactory{
		querier: app.NewLightQueryFactory(rooter, syncer),
	}
}

// QueryAt returns a governance query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
