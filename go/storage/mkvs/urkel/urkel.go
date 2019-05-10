// Package urkel provides an Urkel tree implementation.
package urkel

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

// Re-export the node structures, as we need them in the storage API.
type NodeID = internal.NodeID
type Node = internal.Node
type Pointer = internal.Pointer
type InternalNode = internal.InternalNode
type LeafNode = internal.LeafNode
type Value = internal.Value

type Stats struct {
	MaxDepth          uint8
	InternalNodeCount uint64
	LeafNodeCount     uint64
	LeafValueSize     uint64
	DeadNodeCount     uint64

	LeftSubtreeMaxDepths  map[uint8]uint8
	RightSubtreeMaxDepths map[uint8]uint8

	Cache struct {
		InternalNodeCount uint64
		LeafNodeCount     uint64
		LeafValueSize     uint64
	}
}

// Tree is an Urkel tree.
type Tree struct {
	cache cache

	// NOTE: This can be a map as updates are commutative.
	pendingWriteLog map[hash.Hash]*pendingLogEntry
}

type pendingLogEntry struct {
	key     []byte
	value   []byte
	existed bool
}

// Option is a configuration option used when instantiating the tree.
type Option func(t *Tree)

// PrefetchDepth sets the depth of subtree prefetching.
//
// If no prefetch depth is specified, no prefetching will be done.
func PrefetchDepth(depth uint8) Option {
	return func(t *Tree) {
		t.cache.prefetchDepth = depth
	}
}

// Capacity sets the capacity of the in-memory cache.
//
// If no capacity is specified, the cache will have an unlimited size.
func Capacity(nodeCapacity uint64, valueCapacityBytes uint64) Option {
	return func(t *Tree) {
		t.cache.nodeCapacity = nodeCapacity
		t.cache.valueCapacity = valueCapacityBytes
	}
}

// SyncerGetNodeTimeout sets the timeout for remote node fetches.
//
// If not specified, the default of 1 second will be used.
func SyncerGetNodeTimeout(timeout time.Duration) Option {
	return func(t *Tree) {
		t.cache.syncerGetNodeTimeout = timeout
	}
}

// SyncerPrefetchTimeout sets the timeout for remote subtree fetches.
//
// If not specified, the default of 5 seconds will be used.
func SyncerPrefetchTimeout(timeout time.Duration) Option {
	return func(t *Tree) {
		t.cache.syncerPrefetchTimeout = timeout
	}
}

// New creates a new empty Urkel tree backed by the given node database.
func New(rs syncer.ReadSyncer, ndb db.NodeDB, options ...Option) *Tree {
	if rs == nil {
		rs = syncer.NewNopReadSyncer()
	}
	if ndb == nil {
		ndb, _ = db.NewNopNodeDB()
	}

	t := &Tree{
		cache:           newCache(ndb, rs),
		pendingWriteLog: make(map[hash.Hash]*pendingLogEntry),
	}

	for _, v := range options {
		v(t)
	}

	return t
}

// NewWithRoot creates a new Urkel tree with an existing root, backed by
// the given node database.
func NewWithRoot(ctx context.Context, rs syncer.ReadSyncer, ndb db.NodeDB, root hash.Hash, options ...Option) (*Tree, error) {
	t := New(rs, ndb, options...)
	t.cache.setPendingRoot(&internal.Pointer{
		Clean: true,
		Hash:  root,
	})
	t.cache.setSyncRoot(root)

	// Try to prefetch the subtree at the root.
	// NOTE: Path can be anything here as the depth is 0 so it is actually ignored.
	var path hash.Hash
	ptr, err := t.cache.prefetch(ctx, root, path, 0)
	if err != nil {
		return nil, err
	}
	if ptr != nil {
		t.cache.setPendingRoot(ptr)
	}

	return t, nil
}

// HasRoot checks the given NodeDB to see if the given root exists.
func HasRoot(ndb db.NodeDB, root hash.Hash) bool {
	_, err := ndb.GetNode(root, &internal.Pointer{
		Clean: true,
		Hash:  root,
	})
	return err != db.ErrNodeNotFound
}

// Insert inserts a key/value pair into the tree.
func (t *Tree) Insert(ctx context.Context, key []byte, value []byte) error {
	hkey := hashKey(key)
	var existed bool
	newRoot, existed, err := t.doInsert(ctx, t.cache.pendingRoot, 0, hkey, value)
	if err != nil {
		return err
	}

	// Update the pending write log.
	entry := t.pendingWriteLog[hkey]
	if entry == nil {
		t.pendingWriteLog[hkey] = &pendingLogEntry{key, value, existed}
	} else {
		entry.value = value
	}

	t.cache.setPendingRoot(newRoot)
	return nil
}

// Remove removes a key from the tree.
func (t *Tree) Remove(ctx context.Context, key []byte) error {
	hkey := hashKey(key)
	var changed bool
	newRoot, changed, err := t.doRemove(ctx, t.cache.pendingRoot, 0, hkey)
	if err != nil {
		return err
	}

	// Update the pending write log.
	entry := t.pendingWriteLog[hkey]
	if entry == nil {
		t.pendingWriteLog[hkey] = &pendingLogEntry{key, nil, changed}
	} else {
		entry.value = nil
	}

	t.cache.setPendingRoot(newRoot)
	return nil
}

// Get looks up an existing key.
func (t *Tree) Get(ctx context.Context, key []byte) ([]byte, error) {
	hkey := hashKey(key)
	return t.doGet(ctx, t.cache.pendingRoot, 0, hkey)
}

// Dump dumps the tree into the given writer.
func (t *Tree) Dump(ctx context.Context, w io.Writer) {
	t.doDump(ctx, w, t.cache.pendingRoot, hash.Hash{}, 0)
	fmt.Fprintln(w, "")
}

// Stats traverses the tree and dumps some statistics.
func (t *Tree) Stats(ctx context.Context, maxDepth uint8) Stats {
	stats := &Stats{
		LeftSubtreeMaxDepths:  make(map[uint8]uint8),
		RightSubtreeMaxDepths: make(map[uint8]uint8),
	}
	stats.Cache.InternalNodeCount = t.cache.internalNodeCount
	stats.Cache.LeafNodeCount = t.cache.leafNodeCount
	stats.Cache.LeafValueSize = t.cache.valueSize

	t.doStats(ctx, stats, t.cache.pendingRoot, hash.Hash{}, 0, maxDepth)
	return *stats
}

// Commit commits tree updates to the underlying database and returns
// the write log and new merkle root.
func (t *Tree) Commit(ctx context.Context) (WriteLog, hash.Hash, error) {
	batch := t.cache.db.NewBatch()
	defer batch.Reset()

	updates := &cacheUpdates{}
	root, err := doCommit(ctx, &t.cache, updates, batch, t.cache.pendingRoot)
	if err != nil {
		return nil, hash.Hash{}, err
	}

	if err := batch.Commit(root); err != nil {
		return nil, hash.Hash{}, err
	}
	updates.Commit()

	var log WriteLog
	for _, entry := range t.pendingWriteLog {
		// Skip all entries that do not exist after all the updates and
		// did not exist before.
		if entry.value == nil && !entry.existed {
			continue
		}

		log = append(log, LogEntry{Key: entry.key, Value: entry.value})
	}
	t.pendingWriteLog = make(map[hash.Hash]*pendingLogEntry)
	t.cache.setSyncRoot(root)

	return log, root, nil
}

// Size calculates the size of the tree in bytes.
func (t *Tree) Size() uint64 {
	return t.cache.valueSize
}
