package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

type contextKey string

const (
	contextKeyNodePriorityHint = contextKey("storage/node-priority-key")

	contextKeyNodeBlacklist = contextKey("storage/node-blacklist")

	contextKeyNodeSelectionCallback = contextKey("storage/node-selection-callback")
)

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

// WithNodeBlacklist sets a storage blacklist key for any storage requests using this context.
// The blacklist is initially empty (i.e. all nodes are acceptable).
func WithNodeBlacklist(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyNodeBlacklist, map[signature.PublicKey]struct{}{})
}

// BlacklistAddNode adds a node to the blacklist associated with the context. If there's no
// associated blacklist, the function does nothing.
func BlacklistAddNode(ctx context.Context, node *node.Node) {
	list, _ := ctx.Value(contextKeyNodeBlacklist).(map[signature.PublicKey]struct{})
	if list != nil {
		list[node.ID] = struct{}{}
	}
}

// IsNodeBlacklistedInContext checks to see if the node is blacklisted in this context.
// If the context doesn't have an associated blacklist, then no node is considered blacklisted.
func IsNodeBlacklistedInContext(ctx context.Context, node *node.Node) bool {
	val, ok := ctx.Value(contextKeyNodeBlacklist).(map[signature.PublicKey]struct{})
	if !ok {
		return false
	}
	_, ok = val[node.ID]
	return ok
}

// NodeSelectionCallback is a callback used by the storage client to report connections used
// for read requests.
type NodeSelectionCallback = func(*node.Node)

// WithNodeSelectionCallback sets a callback that will be called by the storage client on every read
// request with the node that was eventually used to perform a successful request. If there was no
// success, the callback isn't called.
func WithNodeSelectionCallback(ctx context.Context, cb NodeSelectionCallback) context.Context {
	return context.WithValue(ctx, contextKeyNodeSelectionCallback, cb)
}

// NodeSelectionCallbackFromContext returns the node selection callback associated with this context
// or nil if none is set.
func NodeSelectionCallbackFromContext(ctx context.Context) NodeSelectionCallback {
	val, _ := ctx.Value(contextKeyNodeSelectionCallback).(NodeSelectionCallback)
	return val
}
