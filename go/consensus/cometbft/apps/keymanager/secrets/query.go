package secrets

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// Query is the key manager query interface.
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

func (kq *querier) Status(ctx context.Context, runtimeID common.Namespace) (*secrets.Status, error) {
	return kq.state.Status(ctx, runtimeID)
}

func (kq *querier) Statuses(ctx context.Context) ([]*secrets.Status, error) {
	return kq.state.Statuses(ctx)
}

func (kq *querier) MasterSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedMasterSecret, error) {
	return kq.state.MasterSecret(ctx, runtimeID)
}

func (kq *querier) EphemeralSecret(ctx context.Context, runtimeID common.Namespace) (*secrets.SignedEncryptedEphemeralSecret, error) {
	return kq.state.EphemeralSecret(ctx, runtimeID)
}

func (kq *querier) Genesis(ctx context.Context) (*secrets.Genesis, error) {
	statuses, err := kq.state.Statuses(ctx)
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

func NewQuery(state *secretsState.ImmutableState) Query {
	return &querier{state}
}
