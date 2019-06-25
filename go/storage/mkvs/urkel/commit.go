package urkel

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	db "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

// doCommit commits all dirty nodes and values into the underlying node
// database. This operation may cause committed nodes and values to be
// evicted from the in-memory cache.
func doCommit(
	ctx context.Context,
	cache *cache,
	batch db.Batch,
	subtree db.Subtree,
	depth uint8,
	ptr *internal.Pointer,
) (h hash.Hash, err error) {
	if ptr == nil {
		h.Empty()
		return
	} else if ptr.Clean {
		if err = subtree.VisitCleanNode(depth, ptr); err != nil {
			return
		}
		h = ptr.Hash
		return
	}

	// Pointer is not clean, we need to perform some hash computations.

	// NOTE: Irreversible cache operations like clearing the dirty flags
	//       and updating node/value cache status must be queued via batch
	//       on-commit hooks as the database operations can fail and this
	//       must not cause the in-memory cache to be corrupted.

	switch n := ptr.Node.(type) {
	case nil:
		// Dead node.
		ptr.Hash.Empty()
	case *internal.InternalNode:
		// Internal node.
		if n.Clean {
			panic("urkel: non-clean pointer has clean node")
		}

		newSubtree := batch.MaybeStartSubtree(subtree, depth+1, n.Left)
		if _, err = doCommit(ctx, cache, batch, newSubtree, depth+1, n.Left); err != nil {
			return
		}
		if newSubtree != subtree {
			if err = newSubtree.Commit(); err != nil {
				return
			}
		}

		newSubtree = batch.MaybeStartSubtree(subtree, depth+1, n.Right)
		if _, err = doCommit(ctx, cache, batch, newSubtree, depth+1, n.Right); err != nil {
			return
		}
		if newSubtree != subtree {
			if err = newSubtree.Commit(); err != nil {
				return
			}
		}

		n.UpdateHash()

		// Store the node.
		if err = subtree.PutNode(depth, ptr); err != nil {
			return
		}

		batch.OnCommit(func() {
			n.Clean = true
		})
		ptr.Hash = n.Hash
	case *internal.LeafNode:
		// Leaf node.
		if n.Clean {
			panic("urkel: non-clean pointer has clean node")
		}

		if !n.Value.Clean {
			n.Value.UpdateHash()

			batch.OnCommit(func() {
				n.Value.Clean = true
				cache.commitValue(n.Value)
			})
		}

		n.UpdateHash()

		// Store the node.
		if err = subtree.PutNode(depth, ptr); err != nil {
			return
		}

		batch.OnCommit(func() {
			n.Clean = true
		})
		ptr.Hash = n.Hash
	}

	batch.OnCommit(func() {
		ptr.Clean = true
		cache.commitNode(ptr)
	})
	h = ptr.Hash
	return
}
