package secrets

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// Query is the key manager secrets query.
type Query struct {
	state *secretsState.ImmutableState
}

// NewQuery creates a new key manager secrets query.
func NewQuery(state *secretsState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// ConsensusParameters implements secrets.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*secrets.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// Status implements secrets.Query.
func (q *Query) Status(ctx context.Context, runtimeID common.Namespace) (*secrets.Status, error) {
	return q.state.Status(ctx, runtimeID)
}

// Statuses implements secrets.Query.
func (q *Query) Statuses(ctx context.Context) ([]*secrets.Status, error) {
	return q.state.Statuses(ctx)
}

// MasterSecret implements secrets.Query.
func (q *Query) MasterSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedMasterSecret, error) {
	return q.state.MasterSecret(ctx, runtimeID)
}

// EphemeralSecret implements secrets.Query.
func (q *Query) EphemeralSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error) {
	return q.state.EphemeralSecret(ctx, runtimeID)
}

// Genesis implements secrets.Query.
func (q *Query) Genesis(ctx context.Context) (*secrets.Genesis, error) {
	parameters, err := q.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	statuses, err := q.state.Statuses(ctx)
	if err != nil {
		return nil, err
	}

	for _, status := range statuses {
		status.Nodes = nil
	}

	gen := secrets.Genesis{
		Parameters: *parameters,
		Statuses:   statuses,
	}
	return &gen, nil
}
