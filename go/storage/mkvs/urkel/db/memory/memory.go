// Package memory provides a memory-backed node database.
package memory

import (
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var _ api.NodeDB = (*memoryNodeDB)(nil)

type memoryItem struct {
	refs  int
	value interface{}
}

type memoryNodeDB struct {
	sync.RWMutex

	items map[hash.Hash]*memoryItem
}

// New creates a new in-memory node database.
func New() (api.NodeDB, error) {
	return &memoryNodeDB{
		items: make(map[hash.Hash]*memoryItem),
	}, nil
}

func (d *memoryNodeDB) GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel: attempted to get invalid pointer from node database")
	}

	d.RLock()
	defer d.RUnlock()

	item, err := d.getLocked(ptr.Hash)
	if err != nil {
		return nil, err
	}

	return item.(internal.Node), nil
}

func (d *memoryNodeDB) GetValue(id hash.Hash) ([]byte, error) {
	d.RLock()
	defer d.RUnlock()

	item, err := d.getLocked(id)
	if err != nil {
		return nil, err
	}

	return item.([]byte), nil
}

func (d *memoryNodeDB) Close() {
}

func (d *memoryNodeDB) putLocked(id hash.Hash, item interface{}) error {
	n := d.items[id]
	if n == nil {
		n = new(memoryItem)
		d.items[id] = n
	}

	n.refs++
	n.value = item

	return nil
}

func (d *memoryNodeDB) getLocked(id hash.Hash) (interface{}, error) {
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

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *internal.Pointer) api.Subtree {
	if subtree == nil {
		return &memorySubtree{batch: b}
	}
	return subtree
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

func (s *memorySubtree) PutNode(depth uint8, ptr *internal.Pointer) error {
	switch n := ptr.Node.(type) {
	case *internal.InternalNode:
		s.batch.ops = append(s.batch.ops, func() error {
			return s.batch.db.putLocked(n.Hash, ptr.Node)
		})
	case *internal.LeafNode:
		s.batch.ops = append(s.batch.ops, func() error {
			_ = s.batch.db.putLocked(n.Value.Hash, n.Value.Value)
			return s.batch.db.putLocked(n.Hash, ptr.Node)
		})
	}
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth uint8, ptr *internal.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
