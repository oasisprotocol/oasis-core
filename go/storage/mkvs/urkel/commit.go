package urkel

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

// cacheUpdates contains a list of pending cache updates to be applied
// after another operation (e.g., a database commit) has succeeded to
// avoid corrupting the in-memory cache.
type cacheUpdates struct {
	updates []func()
}

// Add queues a cache update function.
func (u *cacheUpdates) Add(update func()) {
	u.updates = append(u.updates, update)
}

// Commit runs all the queued cache update functions in order.
func (u *cacheUpdates) Commit() {
	for _, update := range u.updates {
		update()
	}
	u.updates = []func(){}
}

// doCommit commits all dirty nodes and values into the underlying node
// database. This operation may cause committed nodes and values to be
// evicted from the in-memory cache.
func doCommit(cache *cache, upd *cacheUpdates, batch db.Batch, ptr *internal.Pointer) (h hash.Hash, err error) {
	if ptr == nil {
		h.Empty()
		return
	} else if ptr.Clean {
		h = ptr.Hash
		return
	}

	// Pointer is not clean, we need to perform some hash computations.

	// NOTE: Irreversible cache operations like clearing the dirty flags
	//       and updating node/value cache status must be queued via the
	//       provided cacheUpdates instance as the database operations
	//       can fail and this must not cause the in-memory cache to be
	//       corrupted.

	switch n := ptr.Node.(type) {
	case nil:
		// Dead node.
		ptr.Hash.Empty()
	case *internal.InternalNode:
		// Internal node.
		if n.Clean {
			ptr.Hash = n.Hash
			break
		}

		if _, err = doCommit(cache, upd, batch, n.Left); err != nil {
			return
		}
		if _, err = doCommit(cache, upd, batch, n.Right); err != nil {
			return
		}

		n.UpdateHash()

		if cerr := batch.PutNode(ptr); cerr != nil {
			err = cerr
			return
		}

		upd.Add(func() {
			n.Clean = true
		})
		ptr.Hash = n.Hash
	case *internal.LeafNode:
		// Leaf node.
		if n.Clean {
			ptr.Hash = n.Hash
			break
		}

		if !n.Value.Clean {
			n.Value.UpdateHash()

			if err = batch.PutValue(n.Value.Value); err != nil {
				return
			}

			upd.Add(func() {
				n.Value.Clean = true
				cache.commitValue(n.Value)
			})
		}

		n.UpdateHash()

		if err = batch.PutNode(ptr); err != nil {
			return
		}

		upd.Add(func() {
			n.Clean = true
		})
		ptr.Hash = n.Hash
	}

	upd.Add(func() {
		ptr.Clean = true
		cache.commitNode(ptr)
	})
	h = ptr.Hash
	return
}
