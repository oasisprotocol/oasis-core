package secrets

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// Query is the key manager secrets query interface.
type Query interface {
	Status(context.Context, common.Namespace) (*secrets.Status, error)
	Statuses(context.Context) ([]*secrets.Status, error)
	MasterSecret(context.Context, common.Namespace) (*secrets.SignedEncryptedMasterSecret, error)
	EphemeralSecret(context.Context, common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error)
	Genesis(context.Context) (*secrets.Genesis, error)
}

type querier struct {
	state *secretsState.ImmutableState
}

// Status implements Query.
func (q *querier) Status(ctx context.Context, runtimeID common.Namespace) (*secrets.Status, error) {
	return q.state.Status(ctx, runtimeID)
}

// Statuses implements Query.
func (q *querier) Statuses(ctx context.Context) ([]*secrets.Status, error) {
	return q.state.Statuses(ctx)
}

// MasterSecret implements Query.
func (q *querier) MasterSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedMasterSecret, error) {
	return q.state.MasterSecret(ctx, runtimeID)
}

// EphemeralSecret implements Query.
func (q *querier) EphemeralSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error) {
	return q.state.EphemeralSecret(ctx, runtimeID)
}

// Genesis implements Query.
func (q *querier) Genesis(ctx context.Context) (*secrets.Genesis, error) {
	statuses, err := q.state.Statuses(ctx)
	if err != nil {
		return nil, err
	}

	// Remove the Nodes field of each Status.
	for _, status := range statuses {
		status.Nodes = nil
	}

	gen := secrets.Genesis{Statuses: statuses}
	return &gen, nil
}

// NewQuery creates a new key manager secrets query.
func NewQuery(state *secretsState.ImmutableState) Query {
	return &querier{state}
}
