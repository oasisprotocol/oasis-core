package mkvs

import (
	"context"

	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

var _ Tree = (*tree)(nil)

type tree struct { // nolint: maligned
	cache *cache

	rootType node.RootType

	// NOTE: This can be a map as updates are commutative.
	pendingWriteLog map[string]*pendingEntry
	withoutWriteLog bool
	// pendingRemovedNodes are the nodes that have been removed from the
	// in-memory tree and should be marked for garbage collection if this
	// tree is committed to the node database.
	pendingRemovedNodes []node.Node
}

type pendingEntry struct {
	key     []byte
	value   []byte
	existed bool

	insertedLeaf *node.Pointer
}

// Option is a configuration option used when instantiating the tree.
type Option func(t *tree)

// Capacity sets the capacity of the in-memory cache.
//
// If no capacity is specified, the cache will have a maximum capacity of
// 16MB for values and 5000 for nodes.
//
// If a capacity of 0 is specified, the cache will have an unlimited size
// (not recommended, as this will cause unbounded memory growth).
func Capacity(nodeCapacity, valueCapacityBytes uint64) Option {
	return func(t *tree) {
		t.cache.nodeCapacity = nodeCapacity
		t.cache.valueCapacity = valueCapacityBytes
	}
}

// PersistEverythingFromSyncer sets whether to persist all the nodes and
// values obtained from the remote syncer to local database.
//
// If not specified, the default is false.
func PersistEverythingFromSyncer(doit bool) Option {
	return func(t *tree) {
		t.cache.persistEverythingFromSyncer = doit
	}
}

// WithoutWriteLog disables building a write log when performing operations.
//
// Note that this option cannot be used together with specifying a ReadSyncer and trying to use it
// with a tree that also specifies a non-nil ReadSyncer will cause a panic.
func WithoutWriteLog() Option {
	return func(t *tree) {
		if t.cache.rs != syncer.NopReadSyncer {
			panic("mkvs: WithoutWriteLog cannot be used on a tree with a non-nil ReadSyncer")
		}
		t.withoutWriteLog = true
	}
}

// New creates a new empty MKVS tree backed by the given node database.
func New(rs syncer.ReadSyncer, ndb db.NodeDB, rootType node.RootType, options ...Option) Tree {
	if rs == nil {
		rs = syncer.NopReadSyncer
	}
	if ndb == nil {
		ndb, _ = db.NewNopNodeDB()
	}

	t := &tree{
		cache:           newCache(ndb, rs, rootType),
		rootType:        rootType,
		pendingWriteLog: make(map[string]*pendingEntry),
		withoutWriteLog: false,
	}

	for _, v := range options {
		v(t)
	}

	return t
}

// NewWithRoot creates a new MKVS tree with an existing root, backed by
// the given node database.
func NewWithRoot(rs syncer.ReadSyncer, ndb db.NodeDB, root node.Root, options ...Option) Tree {
	t := New(rs, ndb, root.Type, options...).(*tree)
	t.cache.setPendingRoot(&node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	t.cache.setSyncRoot(root)
	return t
}

// Implements Tree.
func (t *tree) NewIterator(ctx context.Context, options ...IteratorOption) Iterator {
	return newTreeIterator(ctx, t, options...)
}

// Implements Tree.
func (t *tree) ApplyWriteLog(ctx context.Context, wl writelog.Iterator) error {
	for {
		// Fetch next entry from write log iterator.
		more, err := wl.Next()
		if err != nil {
			return err
		}
		if !more {
			break
		}
		entry, err := wl.Value()
		if err != nil {
			return err
		}

		// Apply operation.
		if entry.Value == nil {
			err = t.Remove(ctx, entry.Key)
		} else {
			err = t.Insert(ctx, entry.Key, entry.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Implements Tree.
func (t *tree) RootType() node.RootType {
	return t.rootType
}

// Implements Tree.
func (t *tree) Close() {
	t.cache.Lock()
	defer t.cache.Unlock()

	t.cache.close()
	t.pendingWriteLog = nil
}
