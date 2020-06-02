// Package syncer provides the read-only sync interface.
package syncer

import (
	"context"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var (
	// ErrDirtyRoot is the error returned when a ReadSyncer tries to sync from a
	// tree with a dirty root (e.g., a root with local modifications).
	ErrDirtyRoot = errors.New("mkvs: root is dirty")
	// ErrInvalidRoot is the error returned when a ReadSyncer tries to sync from a
	// tree with a different root.
	ErrInvalidRoot = errors.New("mkvs: invalid root")
	// ErrUnsupported is the error returned when a ReadSyncer method is not supported.
	ErrUnsupported = errors.New("mkvs: method not supported")
)

// TreeID identifies a specific tree and a position within that tree.
type TreeID struct {
	// Root is the Merkle tree root.
	Root node.Root `json:"root"`
	// Position is the caller's position in the tree structure to allow
	// returning partial proofs if possible.
	Position hash.Hash `json:"position"`
}

// GetRequest is a request for the SyncGet operation.
type GetRequest struct {
	Tree            TreeID `json:"tree"`
	Key             []byte `json:"key"`
	IncludeSiblings bool   `json:"include_siblings,omitempty"`
}

// GetPrefixesRequest is a request for the SyncGetPrefixes operation.
type GetPrefixesRequest struct {
	Tree     TreeID   `json:"tree"`
	Prefixes [][]byte `json:"prefixes"`
	Limit    uint16   `json:"limit"`
}

// IterateRequest is a request for the SyncIterate operation.
type IterateRequest struct {
	Tree     TreeID `json:"tree"`
	Key      []byte `json:"key"`
	Prefetch uint16 `json:"prefetch"`
}

// ProofResponse is a response for requests that produce proofs.
type ProofResponse struct {
	Proof Proof `json:"proof"`
}

// ReadSyncer is the interface for synchronizing the in-memory cache
// with another (potentially untrusted) MKVS.
type ReadSyncer interface {
	// SyncGet fetches a single key and returns the corresponding proof.
	SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error)

	// SyncGetPrefixes fetches all keys under the given prefixes and returns
	// the corresponding proofs.
	SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error)

	// SyncIterate seeks to a given key and then fetches the specified
	// number of following items based on key iteration order.
	SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error)
}

// nopReadSyncer is a no-op read syncer.
type nopReadSyncer struct{}

// NopReadSyncer is a no-op read syncer.
var NopReadSyncer = &nopReadSyncer{}

func (r *nopReadSyncer) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	return nil, ErrUnsupported
}

func (r *nopReadSyncer) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	return nil, ErrUnsupported
}

func (r *nopReadSyncer) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	return nil, ErrUnsupported
}
