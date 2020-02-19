package urkel

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
)

// Implements Tree.
func (t *tree) Get(ctx context.Context, key []byte) ([]byte, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
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

	pb := syncer.NewProofBuilder(request.Tree.Position)
	opts := doGetOptions{
		proofBuilder:    pb,
		includeSiblings: request.IncludeSiblings,
	}
	if _, err := t.doGet(ctx, t.cache.pendingRoot, 0, request.Key, opts, false); err != nil {
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
		proofRoot := pb.GetRoot()
		if pb.HasRoot() || proofRoot.Equal(&ptr.Hash) {
			pb.Include(nd)
		}
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
			// Omit the proof builder as the leaf node is always included with
			// the internal node itself.
			opts.proofBuilder = nil
			return t.doGet(ctx, n.LeafNode, bitLength, key, opts, false)
		}

		// Lookup key is too short for the current n.Label. It's not stored.
		if key.BitLength() < bitLength {
			return nil, nil
		}

		// Continue recursively based on a bit value.
		var value []byte
		if key.GetBit(bitLength) {
			value, err = t.doGet(ctx, n.Right, bitLength, key, opts, false)
			if err != nil {
				return nil, err
			}

			if opts.includeSiblings {
				// Also fetch the left sibling.
				_, err = t.doGet(ctx, n.Left, bitLength, key, opts, true)
				if err != nil {
					return nil, err
				}
			}
			return value, nil
		}

		value, err = t.doGet(ctx, n.Left, bitLength, key, opts, false)
		if err != nil {
			return nil, err
		}

		if opts.includeSiblings {
			// Also fetch the right sibling.
			_, err = t.doGet(ctx, n.Right, bitLength, key, opts, true)
			if err != nil {
				return nil, err
			}
		}
		return value, nil
	case *node.LeafNode:
		// Reached a leaf node, check if key matches.
		if n.Key.Equal(key) {
			return n.Value, nil
		}
	default:
		panic(fmt.Sprintf("urkel: unknown node type: %+v", n))
	}

	return nil, nil
}
