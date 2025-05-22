package secrets

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// QueryFactory is a key manager secrets query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a key manager secrets query implementation.
type Query interface {
	// Status returns status for the given runtime.
	Status(context.Context, common.Namespace) (*secrets.Status, error)
	// Statuses returns all statuses.
	Statuses(context.Context) ([]*secrets.Status, error)
	// MasterSecret returns the signed and encrypted master secret for the given runtime.
	MasterSecret(context.Context, common.Namespace) (*secrets.SignedEncryptedMasterSecret, error)
	// EphemeralSecret returns the signed and encrypted ephemeral secret for the given runtime.
	EphemeralSecret(context.Context, common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*secrets.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*secrets.ConsensusParameters, error)
}

// StateQueryFactory is a key manager secrets state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new key manager secrets query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a key manager secrets query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}

// LightQueryFactory is a key manager secrets light query factory.
type LightQueryFactory struct {
	querier *app.LightQueryFactory
}

// NewLightQueryFactory returns a new key manager secrets query factory
// backed by a trusted state root provider and an untrusted read syncer.
func NewLightQueryFactory(rooter abciAPI.StateRooter, syncer syncer.ReadSyncer) QueryFactory {
	return &LightQueryFactory{
		querier: app.NewLightQueryFactory(rooter, syncer),
	}
}

// QueryAt returns a key manager secrets query for a specific height.
func (f *LightQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
