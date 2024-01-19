package mkvs

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Use version 0 proofs in sync requests for now.
const syncProofsVersion uint16 = 0

// Implements Tree.
func (t *tree) Get(ctx context.Context, key []byte) ([]byte, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
	}

	// If the key has been modified locally, no need to perform any lookups.
	if !t.withoutWriteLog {
		if entry := t.pendingWriteLog[node.ToMapKey(key)]; entry != nil {
			return entry.value, nil
		}
	}

	// Remember where the path from root to target node ends (will end).
	t.cache.markPosition()

	return t.doGet(ctx, t.cache.pendingRoot, 0, key, doGetOptions{}, false)
}

// Implements syncer.ReadSyncer.
func (t *tree) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
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

	// Remember where the path from root to target node ends (will end).
	t.cache.markPosition()

	pb, err := syncer.NewProofBuilderForVersion(request.Tree.Root.Hash, request.Tree.Position, request.ProofVersion)
	if err != nil {
		return nil, err
	}
	opts := doGetOptions{
		proofBuilder:    pb,
		includeSiblings: request.IncludeSiblings,
	}
	if _, err = t.doGet(ctx, t.cache.pendingRoot, 0, request.Key, opts, false); err != nil {
		return nil, err
	}
	proof, err := pb.Build(ctx)
	if err != nil {
		return nil, err
	}

	return &syncer.ProofResponse{
		Proof: *proof,
	}, nil
}

func (t *tree) newFetcherSyncGet(key node.Key, includeSiblings bool) readSyncFetcher {
	return func(ctx context.Context, ptr *node.Pointer, rs syncer.ReadSyncer) (*syncer.Proof, error) {
		rsp, err := rs.SyncGet(ctx, &syncer.GetRequest{
			Tree: syncer.TreeID{
				Root:     t.cache.syncRoot,
				Position: ptr.Hash,
			},
			Key:             key,
			IncludeSiblings: includeSiblings,
			ProofVersion:    syncProofsVersion,
		})
		if err != nil {
			return nil, err
		}
		return &rsp.Proof, nil
	}
}

type doGetOptions struct {
	proofBuilder    *syncer.ProofBuilder
	includeSiblings bool
}

func (t *tree) doGet(
	ctx context.Context,
	ptr *node.Pointer,
	bitDepth node.Depth,
	key node.Key,
	opts doGetOptions,
	stop bool,
) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Dereference the node, possibly making a remote request.
	nd, err := t.cache.derefNodePtr(ctx, ptr, t.newFetcherSyncGet(key, opts.includeSiblings))
	if err != nil {
		return nil, err
	}

	// Include nodes in proof if we have a proof builder.
	if pb := opts.proofBuilder; pb != nil && ptr != nil {
		pb.Include(nd)
	}

	// This may be used to only include the given node in a proof and not
	// traverse the tree further (e.g., to fetch a sibling).
	if stop {
		return nil, nil
	}

	switch n := nd.(type) {
	case nil:
		// Reached a nil node, there is nothing here.
		return nil, nil
	case *node.InternalNode:
		// Internal node.
		bitLength := bitDepth + n.LabelBitLength

		// Does lookup key end here? Look into LeafNode.
		if key.BitLength() == bitLength {
			if opts.includeSiblings {
				// Also fetch the left and right siblings.
				_, err = t.doGet(ctx, n.Left, bitLength, key, opts, true)
				if err != nil {
					return nil, err
				}
				_, err = t.doGet(ctx, n.Right, bitLength, key, opts, true)
				if err != nil {
					return nil, err
				}
			}

			if pb := opts.proofBuilder; pb != nil && pb.Version() == 0 {
				// Omit the proof builder as the leaf node is always included with
				// the internal node itself in V0 proofs.
				opts.proofBuilder = nil
			}

			return t.doGet(ctx, n.LeafNode, bitLength, key, opts, false)
		}

		// Lookup key is too short for the current n.Label. It's not stored.
		if key.BitLength() < bitLength {
			return nil, nil
		}

		// Continue recursively based on a bit value.
		fn := func(visit, other, leaf *node.Pointer) ([]byte, error) {
			value, err := t.doGet(ctx, visit, bitLength, key, opts, false)
			if err != nil {
				return nil, err
			}

			if opts.includeSiblings {
				if pb := opts.proofBuilder; pb != nil && pb.Version() > 0 {
					// In V0, the leaf node is included in internal node.
					// Also fetch the leaf.
					_, err = t.doGet(ctx, leaf, bitLength, key, opts, true)
					if err != nil {
						return nil, err
					}
				}

				// Also fetch the other sibling.
				_, err = t.doGet(ctx, other, bitLength, key, opts, true)
				if err != nil {
					return nil, err
				}
			}
			return value, nil
		}
		switch key.GetBit(bitLength) {
		case true:
			return fn(n.Right, n.Left, n.LeafNode)
		default:
			return fn(n.Left, n.Right, n.LeafNode)
		}
	case *node.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(key) {
			return n.Value, nil
		}
	default:
		panic(fmt.Sprintf("mkvs: unknown node type: %+v", n))
	}

	return nil, nil
}
