package keymanager

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
)

// Query is the key manager query interface.
type Query interface {
	Secrets() secrets.Query
	Churp() churp.Query
}

// QueryFactory is the key manager query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the key manager query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	secretsState, err := secretsState.NewImmutableStateAt(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}

	churpState, err := churpState.NewImmutableStateAt(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}

	return &keymanagerQuerier{
		secretsState: secretsState,
		churpState:   churpState,
	}, nil
}

type keymanagerQuerier struct {
	secretsState *secretsState.ImmutableState
	churpState   *churpState.ImmutableState
}

func (kq *keymanagerQuerier) Secrets() secrets.Query {
	return secrets.NewQuery(kq.secretsState)
}

func (kq *keymanagerQuerier) Churp() churp.Query {
	return churp.NewQuery(kq.churpState)
}

func (app *keymanagerApplication) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
