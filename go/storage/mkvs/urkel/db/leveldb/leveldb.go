// Package leveldb provides a LevelDB-backed node database.
package leveldb

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

var (
	_ api.NodeDB = (*leveldbNodeDB)(nil)

	nodeKeyPrefix = []byte{'N'}
)

type leveldbNodeDB struct {
	db *leveldb.DB

	closeOnce sync.Once
}

// New creates a new LevelDB-backed node database.
func New(dirname string) (api.NodeDB, error) {
	db, err := leveldb.OpenFile(dirname, nil)
	if err != nil {
		return nil, err
	}

	return &leveldbNodeDB{db: db}, nil
}

func (d *leveldbNodeDB) GetNode(root hash.Hash, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/leveldb: attempted to get invalid pointer from node database")
	}

	bytes, err := d.db.Get(append(nodeKeyPrefix, ptr.Hash[:]...), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			err = api.ErrNodeNotFound
		}
		return nil, err
	}

	return node.UnmarshalBinary(bytes)
}

func (d *leveldbNodeDB) Close() {
	d.closeOnce.Do(func() {
		_ = d.db.Close()
	})
}

type leveldbBatch struct {
	api.BaseBatch

	db  *leveldbNodeDB
	bat *leveldb.Batch
}

func (d *leveldbNodeDB) NewBatch() api.Batch {
	return &leveldbBatch{
		db:  d,
		bat: new(leveldb.Batch),
	}
}

func (b *leveldbBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &leveldbSubtree{batch: b}
	}
	return subtree
}

func (b *leveldbBatch) Commit(root hash.Hash) error {
	if err := b.db.db.Write(b.bat, &opt.WriteOptions{Sync: true}); err != nil {
		return err
	}

	b.Reset()

	return b.BaseBatch.Commit(root)
}

func (b *leveldbBatch) Reset() {
	b.bat.Reset()
}

type leveldbSubtree struct {
	batch *leveldbBatch
}

func (s *leveldbSubtree) PutNode(depth uint8, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	s.batch.bat.Put(append(nodeKeyPrefix, h[:]...), data)
	return nil
}

func (s *leveldbSubtree) VisitCleanNode(depth uint8, ptr *node.Pointer) error {
	return nil
}

func (s *leveldbSubtree) Commit() error {
	return nil
}
