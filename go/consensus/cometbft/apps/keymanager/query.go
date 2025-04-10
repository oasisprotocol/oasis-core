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
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return &keymanagerQuerier{
		secretsState: secretsState.NewImmutableState(state),
		churpState:   churpState.NewImmutableState(state),
	}, nil
}

type keymanagerQuerier struct {
	secretsState *secretsState.ImmutableState
	churpState   *churpState.ImmutableState
}

func (q *keymanagerQuerier) Secrets() secrets.Query {
	return secrets.NewQuery(q.secretsState)
}

func (q *keymanagerQuerier) Churp() churp.Query {
	return churp.NewQuery(q.churpState)
}

func (app *Application) QueryFactory() any {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
