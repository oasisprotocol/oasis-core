// Package memory provides a memory-backed node database.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var _ api.NodeDB = (*memoryNodeDB)(nil)

type doubleHash [2 * hash.Size]byte

type memoryItem struct {
	refs  int
	value []byte
}

type writeLogDigest []logEntryDigest

type logEntryDigest struct {
	key  []byte
	leaf *node.LeafNode
}

type memoryNodeDB struct {
	api.CheckpointableDB

	sync.RWMutex

	items     map[hash.Hash]*memoryItem
	writeLogs map[doubleHash]writeLogDigest
}

func (h doubleHash) fromRoots(startRoot node.Root, endRoot node.Root) {
	copy(h[:hash.Size], startRoot.Hash[:])
	copy(h[hash.Size:], endRoot.Hash[:])
}

// New creates a new in-memory node database.
func New() (api.NodeDB, error) {
	db := &memoryNodeDB{
		items:     make(map[hash.Hash]*memoryItem),
		writeLogs: make(map[doubleHash]writeLogDigest),
	}
	db.CheckpointableDB = api.NewCheckpointableDB(db)
	return db, nil
}

func (d *memoryNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel: attempted to get invalid pointer from node database")
	}

	d.RLock()
	defer d.RUnlock()

	raw, err := d.getLocked(ptr.Hash)
	if err != nil {
		return nil, err
	}

	return node.UnmarshalBinary(raw)
}

func (d *memoryNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, errors.New("urkel/db/memory: end root must follow start root")
	}

	d.RLock()
	defer d.RUnlock()

	var key doubleHash
	key.fromRoots(startRoot, endRoot)

	log, ok := d.writeLogs[key]
	if !ok {
		return nil, api.ErrWriteLogNotFound
	}

	writeLog := make(writelog.WriteLog, len(log))
	for idx, entry := range log {
		writeLog[idx] = writelog.LogEntry{
			Key:   entry.key,
			Value: entry.leaf.Value.Value,
		}
	}

	return api.NewStaticWriteLogIterator(writeLog), nil
}

func (d *memoryNodeDB) HasRoot(root node.Root) bool {
	_, err := d.GetNode(root, &node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	return err != api.ErrNodeNotFound
}

func (d *memoryNodeDB) Close() {
}

func (d *memoryNodeDB) putLocked(id hash.Hash, item []byte) error {
	n := d.items[id]
	if n == nil {
		n = new(memoryItem)
		d.items[id] = n
	}

	n.refs++
	n.value = item

	return nil
}

func (d *memoryNodeDB) getLocked(id hash.Hash) ([]byte, error) {
	item := d.items[id]
	if item == nil {
		return nil, api.ErrNodeNotFound
	}

	return item.value, nil
}

type memoryBatch struct {
	api.BaseBatch

	db *memoryNodeDB

	ops []func() error
}

func (d *memoryNodeDB) NewBatch() api.Batch {
	return &memoryBatch{
		db: d,
	}
}

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth node.Depth, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &memorySubtree{batch: b}
	}
	return subtree
}

func (b *memoryBatch) PutWriteLog(
	startRoot node.Root,
	endRoot node.Root,
	writeLog writelog.WriteLog,
	annotations writelog.WriteLogAnnotations,
) error {
	if !endRoot.Follows(&startRoot) {
		return errors.New("urkel/db/lru: end root must follow start root")
	}

	var key doubleHash
	key.fromRoots(startRoot, endRoot)

	b.db.Lock()
	defer b.db.Unlock()

	digest := make(writeLogDigest, len(writeLog))
	for idx, entry := range writeLog {
		if annotations[idx].InsertedNode != nil {
			nd := annotations[idx].InsertedNode.Node
			if nd == nil {
				raw, err := b.db.getLocked(annotations[idx].InsertedNode.Hash)
				if err != nil {
					return err
				}

				nd, err = node.UnmarshalBinary(raw)
				if err != nil {
					return err
				}
			}
			digest[idx] = logEntryDigest{
				key:  entry.Key,
				leaf: nd.(*node.LeafNode),
			}
		} else {
			digest[idx] = logEntryDigest{
				key:  entry.Key,
				leaf: nil,
			}
		}
	}

	b.db.writeLogs[key] = digest
	return nil
}

func (b *memoryBatch) Commit(root node.Root) error {
	b.db.Lock()
	defer b.db.Unlock()

	for _, op := range b.ops {
		if err := op(); err != nil {
			return err
		}
	}
	b.Reset()

	return b.BaseBatch.Commit(root)
}

func (b *memoryBatch) Reset() {
	b.ops = nil
}

type memorySubtree struct {
	batch *memoryBatch
}

func (s *memorySubtree) PutNode(depth node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	s.batch.ops = append(s.batch.ops, func() error {
		return s.batch.db.putLocked(ptr.Node.GetHash(), data)
	})
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
