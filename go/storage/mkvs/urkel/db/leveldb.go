package db

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var (
	_ NodeDB = (*leveldbNodeDB)(nil)

	nodeKeyPrefix  = []byte{'N'}
	valueKeyPrefix = []byte{'V'}
)

type leveldbNodeDB struct {
	db *leveldb.DB

	closeOnce sync.Once
}

// NewLevelDBNodeDB creates a new LevelDB-backed node database.
func NewLevelDBNodeDB(dirname string) (NodeDB, error) {
	db, err := leveldb.OpenFile(dirname, nil)
	if err != nil {
		return nil, err
	}

	return &leveldbNodeDB{db: db}, nil
}

// NodeUnmarshalBinary unmarshales internal.Node
func NodeUnmarshalBinary(bytes []byte) (internal.Node, error) {
	// Nodes can be either Internal or Leaf nodes.
	// Check the first byte and deserialize appropriately.
	var node internal.Node
	if len(bytes) > 1 {
		switch bytes[0] {
		case internal.PrefixLeafNode:
			var leaf internal.LeafNode
			if err := leaf.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			node = internal.Node(&leaf)
		case internal.PrefixInternalNode:
			var inode internal.InternalNode
			if err := inode.UnmarshalBinary(bytes); err != nil {
				return nil, err
			}
			node = internal.Node(&inode)
		default:
			panic("urkel/utils: stored node is neither leaf nor internal node")
		}
	} else {
		panic("urkel/utils: stored node is corrupt")
	}
	return node, nil
}

func (d *leveldbNodeDB) GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/leveldb: attempted to get invalid pointer from node database")
	}

	bytes, err := d.db.Get(append(nodeKeyPrefix, ptr.Hash[:]...), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			err = ErrNodeNotFound
		}
		return nil, err
	}

	return NodeUnmarshalBinary(bytes)
}

func (d *leveldbNodeDB) GetValue(id hash.Hash) ([]byte, error) {
	bytes, err := d.db.Get(append(valueKeyPrefix, id[:]...), nil)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (d *leveldbNodeDB) Close() {
	d.closeOnce.Do(func() {
		_ = d.db.Close()
	})
}

type leveldbBatch struct {
	db  *leveldbNodeDB
	bat *leveldb.Batch
}

func (d *leveldbNodeDB) NewBatch() Batch {
	return &leveldbBatch{
		db:  d,
		bat: new(leveldb.Batch),
	}
}

func (b *leveldbBatch) PutNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel/db/leveldb: attempted to put invalid pointer to node database")
	}

	hash := ptr.Node.GetHash()

	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	b.bat.Put(append(nodeKeyPrefix, hash[:]...), data)
	return nil
}

func (b *leveldbBatch) RemoveNode(ptr *internal.Pointer) error {
	if ptr == nil || ptr.Node == nil {
		panic("urkel/db/leveldb: attempted to remove invalid pointer from node database")
	}

	hash := ptr.Node.GetHash()

	b.bat.Delete(append(nodeKeyPrefix, hash[:]...))
	return nil
}

func (b *leveldbBatch) PutValue(value []byte) error {
	var id hash.Hash
	id.FromBytes(value)

	b.bat.Put(append(valueKeyPrefix, id[:]...), value)
	return nil
}

func (b *leveldbBatch) RemoveValue(id hash.Hash) error {
	b.bat.Delete(append(valueKeyPrefix, id[:]...))
	return nil
}

func (b *leveldbBatch) Commit(root hash.Hash) error {
	if err := b.db.db.Write(b.bat, &opt.WriteOptions{Sync: true}); err != nil {
		return err
	}

	b.Reset()

	return nil
}

func (b *leveldbBatch) Reset() {
	b.bat.Reset()
}
