package api

import (
	"bytes"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

// finalizationPendingRuntimesKey is the block context key.
type finalizationPendingRuntimesKey struct{}

func (pk finalizationPendingRuntimesKey) NewDefault() interface{} {
	return make(map[common.Namespace]struct{})
}

// RegisterRuntimeForFinalization appends the given runtime to the list of runtimes considered
// for finalization during the end block.
func RegisterRuntimeForFinalization(ctx *abciAPI.Context, runtimeID common.Namespace) {
	rts := ctx.BlockContext().Get(finalizationPendingRuntimesKey{}).(map[common.Namespace]struct{})

	rts[runtimeID] = struct{}{}
}

// RuntimesToFinalize returns an ordered list of runtimes to be considered for finalization
// during the end block.
func RuntimesToFinalize(ctx *abciAPI.Context) []common.Namespace {
	rts := ctx.BlockContext().Get(finalizationPendingRuntimesKey{}).(map[common.Namespace]struct{})

	// Ensure deterministic order of runtimes.
	sorted := make([]common.Namespace, 0, len(rts))
	for id := range rts {
		sorted = append(sorted, id)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})

	return sorted
}
