package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// HashedDBWriteLog is a write log helper for database backends that can reference nodes by hash.
type HashedDBWriteLog []HashedDBLogEntry

// HashedDBLogEntry is a single write log entry for HashedDBWriteLog.
type HashedDBLogEntry struct {
	Key          []byte
	InsertedHash *hash.Hash
}

// MakeHashedDBWriteLog converts the given write log and annotations into a serializable slice with hash node references.
func MakeHashedDBWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) HashedDBWriteLog {
	log := make(HashedDBWriteLog, len(writeLog))
	for idx, entry := range writeLog {
		var h *hash.Hash
		if annotations[idx].InsertedNode != nil {
			h = &annotations[idx].InsertedNode.Hash
		}
		log[idx] = HashedDBLogEntry{
			Key:          entry.Key,
			InsertedHash: h,
		}
	}
	return log
}

// ReviveHashedDBWriteLogs is a helper for hashed database backends that converts
// a HashedDBWriteLog into a WriteLog.
//
// The provided logGetter will be called first to fetch the next write log to
// convert. If it returns a nil write log, iteration terminates.
//
// Then the provided valueGetter will be called for each log entry to fetch each
// of the values in the write log.
//
// After iteration has finished, closer will be called.
func ReviveHashedDBWriteLogs(
	ctx context.Context,
	logGetter func() (node.Root, HashedDBWriteLog, error),
	valueGetter func(node.Root, hash.Hash) (*node.LeafNode, error),
	closer func(),
) (writelog.Iterator, error) {
	pipe := writelog.NewPipeIterator(ctx)
	go func() {
		defer pipe.Close()
		defer closer()

		for {
			// Return early if context has been cancelled.
			if ctx.Err() != nil {
				return
			}

			// Fetch the next write log from the database.
			root, log, err := logGetter()
			if err != nil {
				_ = pipe.PutError(err)
				return
			}
			if log == nil {
				return
			}

			for _, entry := range log {
				var newEntry *writelog.LogEntry
				if entry.InsertedHash == nil {
					newEntry = &writelog.LogEntry{
						Key:   entry.Key,
						Value: nil,
					}
				} else {
					node, err := valueGetter(root, *entry.InsertedHash)
					if err != nil {
						_ = pipe.PutError(err)
						return
					}
					newEntry = &writelog.LogEntry{
						Key:   entry.Key,
						Value: node.Value,
					}
				}
				if err := pipe.Put(newEntry); err != nil {
					_ = pipe.PutError(err)
					return
				}
			}
		}
	}()
	return &pipe, nil
}

// NodeVisitor is a function that visits a given node and returns true to continue
// traversal of child nodes or false to stop.
type NodeVisitor func(context.Context, node.Node) bool

// Visit traverses the tree in DFS order using the passed visitor. The traversal is
// a pre-order DFS where the node is visited first, then its leaf (if any) and then
// its children (first left then right).
//
// Different to the Visit method in the MKVS tree, this uses the NodeDB API directly
// to traverse the tree to avoid the overhead of keeping the cache.
func Visit(ctx context.Context, ndb NodeDB, root node.Root, visitor NodeVisitor) error {
	ptr := &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}
	return doVisit(ctx, ndb, root, visitor, ptr)
}

func doVisit(ctx context.Context, ndb NodeDB, root node.Root, visitor NodeVisitor, ptr *node.Pointer) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	nd, err := ndb.GetNode(root, ptr)
	if err != nil {
		return err
	}

	if !visitor(ctx, nd) {
		return nil
	}

	if n, ok := nd.(*node.InternalNode); ok {
		if n.LeafNode != nil {
			err = doVisit(ctx, ndb, root, visitor, n.LeafNode)
			if err != nil {
				return err
			}
		}
		if n.Left != nil {
			err = doVisit(ctx, ndb, root, visitor, n.Left)
			if err != nil {
				return err
			}
		}
		if n.Right != nil {
			err = doVisit(ctx, ndb, root, visitor, n.Right)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
