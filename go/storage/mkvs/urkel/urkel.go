// Package urkel provides an Urkel tree implementation.
package urkel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	db "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

// ErrClosed is the error returned when methods are used after Close is called.
var ErrClosed = errors.New("urkel: tree is closed")

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
	cache *cache

	// NOTE: This can be a map as updates are commutative.
	pendingWriteLog map[hash.Hash]*pendingEntry
}

type pendingEntry struct {
	key     []byte
	value   []byte
	existed bool

	insertedLeaf *node.Pointer
	hashedKey    hash.Hash // TODO this should go away once internal keys are the same as api keys (PR#1743)
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
// If no capacity is specified, the cache will have a maximum capacity of
// 16MB for values and 5000 for nodes.
//
// If a capacity of 0 is specified, the cache will have an unlimited size
// (not recommended, as this will cause unbounded memory growth).
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

// PersistEverythingFromSyncer sets whether to persist all the nodes and
// values obtained from the remote syncer to local database.
//
// If not specified, the default is false.
func PersistEverythingFromSyncer(doit bool) Option {
	return func(t *Tree) {
		t.cache.persistEverythingFromSyncer = doit
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
		pendingWriteLog: make(map[hash.Hash]*pendingEntry),
	}

	for _, v := range options {
		v(t)
	}

	return t
}

// NewWithRoot creates a new Urkel tree with an existing root, backed by
// the given node database.
func NewWithRoot(ctx context.Context, rs syncer.ReadSyncer, ndb db.NodeDB, root node.Root, options ...Option) (*Tree, error) {
	t := New(rs, ndb, options...)
	t.cache.setPendingRoot(&node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	t.cache.setSyncRoot(root)

	t.cache.Lock()
	defer t.cache.Unlock()

	// Try to prefetch the subtree at the root.
	// NOTE: Path can be anything here as the depth is 0 so it is actually ignored.
	var path hash.Hash
	ptr, err := t.cache.prefetch(ctx, root.Hash, path, 0)
	if err != nil {
		return nil, err
	}
	if ptr != nil {
		t.cache.setPendingRoot(ptr)
	}

	return t, nil
}

// TODO: Move this to NodeDB.
// HasRoot checks the given NodeDB to see if the given root exists.
func HasRoot(ndb db.NodeDB, root node.Root) bool {
	_, err := ndb.GetNode(root, &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	return err != db.ErrNodeNotFound
}

// Insert inserts a key/value pair into the tree.
func (t *Tree) Insert(ctx context.Context, key []byte, value []byte) error {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return ErrClosed
	}

	hkey := hashKey(key)
	var result insertResult
	result, err := t.doInsert(ctx, t.cache.pendingRoot, 0, hkey, value)
	if err != nil {
		return err
	}

	// Update the pending write log.
	entry := t.pendingWriteLog[hkey]
	if entry == nil {
		t.pendingWriteLog[hkey] = &pendingEntry{
			key:          key,
			value:        value,
			existed:      result.existed,
			insertedLeaf: result.insertedLeaf,
			hashedKey:    hkey,
		}
	} else {
		entry.value = value
	}

	t.cache.setPendingRoot(result.newRoot)
	return nil
}

// Remove removes a key from the tree.
func (t *Tree) Remove(ctx context.Context, key []byte) error {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return ErrClosed
	}

	hkey := hashKey(key)
	var changed bool
	newRoot, changed, err := t.doRemove(ctx, t.cache.pendingRoot, 0, hkey)
	if err != nil {
		return err
	}

	// Update the pending write log.
	entry := t.pendingWriteLog[hkey]
	if entry == nil {
		t.pendingWriteLog[hkey] = &pendingEntry{key, nil, changed, nil, hkey}
	} else {
		entry.value = nil
	}

	t.cache.setPendingRoot(newRoot)
	return nil
}

// Get looks up an existing key.
func (t *Tree) Get(ctx context.Context, key []byte) ([]byte, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, ErrClosed
	}

	hkey := hashKey(key)
	return t.doGet(ctx, t.cache.pendingRoot, 0, hkey)
}

// Dump dumps the tree into the given writer.
func (t *Tree) Dump(ctx context.Context, w io.Writer) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return
	}

	t.doDump(ctx, w, t.cache.pendingRoot, hash.Hash{}, 0)
	fmt.Fprintln(w, "")
}

// Stats traverses the tree and dumps some statistics.
func (t *Tree) Stats(ctx context.Context, maxDepth uint8) Stats {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return Stats{}
	}

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
func (t *Tree) Commit(ctx context.Context, namespace common.Namespace, round uint64) (writelog.WriteLog, hash.Hash, error) {
	t.cache.Lock()
	defer t.cache.Unlock()

	if t.cache.isClosed() {
		return nil, hash.Hash{}, ErrClosed
	}

	batch := t.cache.db.NewBatch()
	defer batch.Reset()

	subtree := batch.MaybeStartSubtree(nil, 0, t.cache.pendingRoot)

	rootHash, err := doCommit(ctx, t.cache, batch, subtree, 0, t.cache.pendingRoot)
	if err != nil {
		return nil, hash.Hash{}, err
	}
	if err := subtree.Commit(); err != nil {
		return nil, hash.Hash{}, err
	}

	var log writelog.WriteLog
	var logAnns writelog.WriteLogAnnotations
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

	oldRoot := t.cache.getSyncRoot()
	if oldRoot.IsEmpty() {
		oldRoot.Namespace = namespace
		oldRoot.Round = round
	}
	root := node.Root{
		Namespace: namespace,
		Round:     round,
		Hash:      rootHash,
	}
	if err := batch.PutWriteLog(oldRoot, root, log, logAnns); err != nil {
		return nil, hash.Hash{}, err
	}

	if err := batch.Commit(root); err != nil {
		return nil, hash.Hash{}, err
	}

	t.pendingWriteLog = make(map[hash.Hash]*pendingEntry)
	t.cache.setSyncRoot(root)

	return log, rootHash, nil
}

// Close releases resources associated with this tree. After calling this
// method the tree MUST NOT be used anymore and all methods will return
// the ErrClosed error.
//
// Any pending write operations are discarded. If you need to persist them
// you need to call Commit before calling this method.
func (t *Tree) Close() {
	t.cache.Lock()
	defer t.cache.Unlock()

	t.cache.close()
	t.pendingWriteLog = nil
}

// Size calculates the size of the tree in bytes.
func (t *Tree) Size() uint64 {
	return t.cache.valueSize
}
