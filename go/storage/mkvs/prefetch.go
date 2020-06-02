package mkvs

import (
	"bytes"
	"context"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Implements Tree.
func (t *tree) PrefetchPrefixes(ctx context.Context, prefixes [][]byte, limit uint16) error {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return ErrClosed
	}
	if t.cache.rs == syncer.NopReadSyncer {
		// If there is no remote syncer, we just do nothing.
		return nil
	}

	return t.doPrefetchPrefixes(ctx, prefixes, limit)
}

func (t *tree) doPrefetchPrefixes(ctx context.Context, prefixes [][]byte, limit uint16) error {
	// TODO: Can we avoid fetching items that we already have?

	return t.cache.remoteSync(
		ctx,
		t.cache.pendingRoot,
		func(ctx context.Context, ptr *node.Pointer, rs syncer.ReadSyncer) (*syncer.Proof, error) {
			rsp, err := rs.SyncGetPrefixes(ctx, &syncer.GetPrefixesRequest{
				Tree: syncer.TreeID{
					Root:     t.cache.syncRoot,
					Position: t.cache.syncRoot.Hash,
				},
				Prefixes: prefixes,
				Limit:    limit,
			})
			if err != nil {
				return nil, err
			}
			return &rsp.Proof, nil
		},
	)
}

// Implements syncer.ReadSyncer.
func (t *tree) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
	}
	if !request.Tree.Root.Equal(&t.cache.syncRoot) {
		return nil, syncer.ErrInvalidRoot
	}
	if !t.cache.pendingRoot.IsClean() {
		return nil, syncer.ErrDirtyRoot
	}

	// First, trigger same prefetching locally if a remote read syncer
	// is available. This is needed to ensure that the same optimization
	// carries on to the next layer.
	if t.cache.rs != syncer.NopReadSyncer {
		err := t.doPrefetchPrefixes(ctx, request.Prefixes, request.Limit)
		if err != nil {
			return nil, err
		}
	}

	it := t.NewIterator(ctx, WithProof(request.Tree.Root.Hash))
	defer it.Close()

	var total int
prefixLoop:
	for _, prefix := range request.Prefixes {
		it.Seek(prefix)
		if it.Err() != nil {
			return nil, it.Err()
		}
		for ; it.Valid(); total++ {
			if total >= int(request.Limit) {
				break prefixLoop
			}
			if !bytes.HasPrefix(it.Key(), prefix) {
				break
			}
			it.Next()
		}
		if it.Err() != nil {
			return nil, it.Err()
		}
	}

	proof, err := it.GetProof()
	if err != nil {
		return nil, err
	}

	return &syncer.ProofResponse{
		Proof: *proof,
	}, nil
}
