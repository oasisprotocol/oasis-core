// Package context implements common context helpers.
package context

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// GetCtxWithGenesisInfo returns a new context with values that contain
// additional from the given genesis file (e.g. token's symbol and token value's
// base-10 exponent, genesis document's hash).
func GetCtxWithGenesisInfo(genesis *genesisAPI.Document) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, genesis.Staking.TokenSymbol)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, genesis.Staking.TokenValueExponent)
	ctx = context.WithValue(ctx, prettyprint.ContextKeyGenesisHash, genesis.Hash())
	return ctx
}
