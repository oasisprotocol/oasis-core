package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

type contextKey string

const contextKeyNodePriorityHint = contextKey("storage/node-priority-key")

// WithNodePriorityHint sets a storage node priority hint for any storage read requests using this
// context. Only storage nodes that overlap with the configured committee will be used.
func WithNodePriorityHint(ctx context.Context, nodes []signature.PublicKey) context.Context {
	return context.WithValue(ctx, contextKeyNodePriorityHint, nodes)
}

// WithNodePriorityHintFromMap sets a storage node priority hint for any storage read requests using this
// context. Only storage nodes that overlap with the configured committee will be used.
func WithNodePriorityHintFromMap(ctx context.Context, nodes map[signature.PublicKey]bool) context.Context {
	priority := make([]signature.PublicKey, 0, len(nodes))
	for k, b := range nodes {
		if b {
			priority = append(priority, k)
		}
	}

	return WithNodePriorityHint(ctx, priority)
}

// WithNodePriorityHintFromSignatures sets a storage node priority hint for any storage read
// requests using this context. Only storage nodes that overlap with the configured committee will
// be used.
func WithNodePriorityHintFromSignatures(ctx context.Context, sigs []signature.Signature) context.Context {
	var nodes []signature.PublicKey
	for _, s := range sigs {
		nodes = append(nodes, s.PublicKey)
	}
	return WithNodePriorityHint(ctx, nodes)
}

// NodePriorityHintFromContext returns the storage node priority hint or nil if none is set.
func NodePriorityHintFromContext(ctx context.Context) []signature.PublicKey {
	nodes, _ := ctx.Value(contextKeyNodePriorityHint).([]signature.PublicKey)
	return nodes
}
