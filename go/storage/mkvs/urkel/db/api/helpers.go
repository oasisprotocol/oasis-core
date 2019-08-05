package api

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
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

// ReviveHashedDBWriteLog is a helper for hashed database backends that converts a HashedDBWriteLog into a WriteLog.
func ReviveHashedDBWriteLog(ctx context.Context, hlog HashedDBWriteLog, getter func(hash.Hash) (*node.LeafNode, error)) (writelog.Iterator, error) {
	pipe := writelog.NewPipeIterator(ctx)
	go func() {
		defer pipe.Close()
		for _, entry := range hlog {
			var newEntry *writelog.LogEntry
			if entry.InsertedHash == nil {
				newEntry = &writelog.LogEntry{
					Key:   entry.Key,
					Value: nil,
				}
			} else {
				node, err := getter(*entry.InsertedHash)
				if err != nil {
					_ = pipe.PutError(err)
					break
				}
				newEntry = &writelog.LogEntry{
					Key:   entry.Key,
					Value: node.Value.Value,
				}
			}
			if err := pipe.Put(newEntry); err != nil {
				_ = pipe.PutError(err)
				break
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
// Different to the Visit method in the Urkel tree, this uses the NodeDB API directly
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
