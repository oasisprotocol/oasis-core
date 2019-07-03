// Package memory provides a memory-backed node database.
package memory

import (
	"context"
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
	sync.RWMutex

	items     map[hash.Hash]*memoryItem
	writeLogs map[doubleHash]writeLogDigest
}

func (h doubleHash) fromHashes(startHash hash.Hash, endHash hash.Hash) {
	copy(h[:hash.Size], startHash[:])
	copy(h[hash.Size:], endHash[:])
}

// New creates a new in-memory node database.
func New() (api.NodeDB, error) {
	return &memoryNodeDB{
		items:     make(map[hash.Hash]*memoryItem),
		writeLogs: make(map[doubleHash]writeLogDigest),
	}, nil
}

func (d *memoryNodeDB) GetNode(root hash.Hash, ptr *node.Pointer) (node.Node, error) {
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

func (d *memoryNodeDB) GetWriteLog(ctx context.Context, startHash hash.Hash, endHash hash.Hash) (api.WriteLogIterator, error) {
	d.RLock()
	defer d.RUnlock()

	var key doubleHash
	key.fromHashes(startHash, endHash)

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

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &memorySubtree{batch: b}
	}
	return subtree
}

func (b *memoryBatch) PutWriteLog(startHash hash.Hash, endHash hash.Hash, writeLog writelog.WriteLog, annotations writelog.WriteLogAnnotations) error {
	var key doubleHash
	key.fromHashes(startHash, endHash)

	b.db.Lock()
	defer b.db.Unlock()

	digest := make(writeLogDigest, len(writeLog))
	for idx, entry := range writeLog {
		if annotations[idx].InsertedNode != nil {
			digest[idx] = logEntryDigest{
				key:  entry.Key,
				leaf: annotations[idx].InsertedNode.Node.(*node.LeafNode),
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

func (b *memoryBatch) Commit(root hash.Hash) error {
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

func (s *memorySubtree) PutNode(depth uint8, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	s.batch.ops = append(s.batch.ops, func() error {
		return s.batch.db.putLocked(ptr.Node.GetHash(), data)
	})
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
