package urkel

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	db "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

// Implements Tree.
func (t *tree) CommitKnown(ctx context.Context, root node.Root) (writelog.WriteLog, error) {
	writeLog, _, err := t.commitWithHooks(ctx, root.Namespace, root.Round, func(rootHash hash.Hash) error {
		if !rootHash.Equal(&root.Hash) {
			return ErrKnownRootMismatch
		}

		return nil
	})
	return writeLog, err
}

// Implements Tree.
func (t *tree) Commit(ctx context.Context, namespace common.Namespace, round uint64) (writelog.WriteLog, hash.Hash, error) {
	return t.commitWithHooks(ctx, namespace, round, nil)
}

func (t *tree) commitWithHooks(
	ctx context.Context,
	namespace common.Namespace,
	round uint64,
	beforeDbCommit func(hash.Hash) error,
) (writelog.WriteLog, hash.Hash, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, hash.Hash{}, ErrClosed
	}

	oldRoot := t.cache.getSyncRoot()
	if oldRoot.IsEmpty() {
		oldRoot.Namespace = namespace
		oldRoot.Round = round
	}

	batch := t.cache.db.NewBatch(oldRoot, false)
	defer batch.Reset()

	subtree := batch.MaybeStartSubtree(nil, 0, t.cache.pendingRoot)

	rootHash, err := doCommit(ctx, t.cache, batch, subtree, 0, t.cache.pendingRoot, &round)
	if err != nil {
		return nil, hash.Hash{}, err
	}
	if err := subtree.Commit(); err != nil {
		return nil, hash.Hash{}, err
	}

	// Perform pre-commit validation if configured.
	if beforeDbCommit != nil {
		if err := beforeDbCommit(rootHash); err != nil {
			return nil, hash.Hash{}, err
		}
	}

	// Store write log summaries.
	var log writelog.WriteLog
	var logAnns writelog.Annotations
	for _, entry := range t.pendingWriteLog {
		// Skip all entries that do not exist after all the updates and
		// did not exist before.
		if entry.value == nil && !entry.existed {
			continue
		}

		log = append(log, writelog.LogEntry{Key: entry.key, Value: entry.value})
		if len(entry.value) == 0 {
			logAnns = append(logAnns, writelog.LogEntryAnnotation{InsertedNode: nil})
		} else {
			logAnns = append(logAnns, writelog.LogEntryAnnotation{InsertedNode: entry.insertedLeaf})
		}
	}

	root := node.Root{
		Namespace: namespace,
		Round:     round,
		Hash:      rootHash,
	}
	if err := batch.PutWriteLog(log, logAnns); err != nil {
		return nil, hash.Hash{}, err
	}

	// Store removed nodes.
	if err := batch.RemoveNodes(t.pendingRemovedNodes); err != nil {
		return nil, hash.Hash{}, err
	}

	// And finally commit to the database.
	if err := batch.Commit(root); err != nil {
		return nil, hash.Hash{}, err
	}

	t.pendingWriteLog = make(map[string]*pendingEntry)
	t.pendingRemovedNodes = nil
	t.cache.setSyncRoot(root)

	return log, rootHash, nil
}

// doCommit commits all dirty nodes and values into the underlying node
// database. This operation may cause committed nodes and values to be
// evicted from the in-memory cache.
func doCommit(
	ctx context.Context,
	cache *cache,
	batch db.Batch,
	subtree db.Subtree,
	depth node.Depth,
	ptr *node.Pointer,
	round *uint64,
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
	case *node.InternalNode:
		// Internal node.
		if n.Clean {
			panic("urkel: non-clean pointer has clean node")
		}

		// Commit internal leaf (considered to be on the same depth as the internal node).
		if _, err = doCommit(ctx, cache, batch, subtree, depth, n.LeafNode, round); err != nil {
			return
		}

		for _, subNode := range []*node.Pointer{n.Left, n.Right} {
			newSubtree := batch.MaybeStartSubtree(subtree, depth+1, subNode)
			if _, err = doCommit(ctx, cache, batch, newSubtree, depth+1, subNode, round); err != nil {
				return
			}
			if newSubtree != subtree {
				if err = newSubtree.Commit(); err != nil {
					return
				}
			}
		}

		if round != nil {
			n.Round = *round
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
	case *node.LeafNode:
		// Leaf node.
		if n.Clean {
			panic("urkel: non-clean pointer has clean node")
		}

		if round != nil {
			n.Round = *round
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
		// Make node eligible for eviction.
		cache.commitNode(ptr)
	})
	h = ptr.Hash
	return
}
