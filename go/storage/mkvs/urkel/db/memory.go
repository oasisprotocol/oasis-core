package db

import (
	"sync"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var _ NodeDB = (*memoryNodeDB)(nil)

type memoryItem struct {
	refs  int
	value interface{}
}

type memoryNodeDB struct {
	sync.RWMutex

	items map[hash.Hash]*memoryItem
}

// NewMemoryNodeDB creates a new in-memory node database.
func NewMemoryNodeDB() NodeDB {
	return &memoryNodeDB{
		items: make(map[hash.Hash]*memoryItem),
	}
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
		return nil, ErrNodeNotFound
	}

	return item.value, nil
}

func (d *memoryNodeDB) removeLocked(id hash.Hash) error {
	item := d.items[id]
	if item == nil {
		return nil
	}

	item.refs--
	if item.refs <= 0 {
		delete(d.items, id)
	}

	return nil
}

type memoryBatch struct {
	db *memoryNodeDB

	ops []func() error
}

func (d *memoryNodeDB) NewBatch() Batch {
	return &memoryBatch{
		db: d,
	}
}

func (b *memoryBatch) PutNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel: attempted to put invalid pointer to node database")
	}

	b.ops = append(b.ops, func() error {
		return b.db.putLocked(ptr.Node.GetHash(), ptr.Node)
	})
	return nil
}

func (b *memoryBatch) RemoveNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel: attempted to remove invalid pointer from node database")
	}

	b.ops = append(b.ops, func() error {
		return b.db.removeLocked(ptr.Node.GetHash())
	})
	return nil
}

func (b *memoryBatch) PutValue(value []byte) error {
	var id hash.Hash
	id.FromBytes(value)

	b.ops = append(b.ops, func() error {
		return b.db.putLocked(id, value)
	})
	return nil
}

func (b *memoryBatch) RemoveValue(id hash.Hash) error {
	b.ops = append(b.ops, func() error {
		return b.db.removeLocked(id)
	})
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

	return nil
}

func (b *memoryBatch) Reset() {
	b.ops = nil
}
