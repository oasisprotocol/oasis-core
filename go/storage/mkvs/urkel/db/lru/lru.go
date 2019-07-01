// Package lru provides a lossy LRU-cache based node database.
package lru

import (
	"bufio"
	"io"
	"os"
	"sync"
	"unsafe"

	"github.com/oasislabs/go-codec/codec"
	"github.com/pkg/errors"

	lruCache "github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	urkel "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

var (
	_ api.NodeDB        = (*lruNodeDB)(nil)
	_ lruCache.Sizeable = (*nodeCacheItem)(nil)
)

type lruNodeDB struct {
	sync.RWMutex

	items *lruCache.Cache
	fname string
}

type nodeCacheItem struct {
	n urkel.Node
}

func (nci *nodeCacheItem) Size() uint64 {
	switch n := nci.n.(type) {
	case *urkel.InternalNode:
		return uint64(unsafe.Sizeof(n))
	case *urkel.LeafNode:
		return uint64(unsafe.Sizeof(n)) + uint64(len(n.Value.Value))
	default:
		return uint64(unsafe.Sizeof(nci.n))
	}
}

// New creates a new in-memory node database with LRU replacement policy based on given size.
func New(sizeInBytes uint64, filename string) (api.NodeDB, error) {
	i, err := lruCache.New(lruCache.Capacity(sizeInBytes, true))
	if err != nil {
		return nil, err
	}

	db := &lruNodeDB{items: i, fname: filename}
	err = db.load()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (d *lruNodeDB) GetNode(root hash.Hash, ptr *urkel.Pointer) (urkel.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/lru: attempted to get invalid pointer from node database")
	}

	d.RLock()
	defer d.RUnlock()

	item, err := d.getLocked(ptr.Hash)
	if err != nil {
		return nil, err
	}

	node := item.(*nodeCacheItem).n
	return node.Extract(), nil
}

func (d *lruNodeDB) Close() {
	_ = d.save()
}

func (d *lruNodeDB) save() error {
	f, err := os.OpenFile(d.fname, os.O_CREATE|os.O_APPEND|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "urkel/db/lru: failed to open cache file for writing")
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	ch := make(chan []byte)

	go func() {
		defer close(ch)

		for _, k := range d.items.Keys() {
			item, _ := d.items.Get(k)

			// Serialize key.
			key := k.(hash.Hash)
			bytes := append([]byte{'K'}, key[:]...)

			// Serialize node.
			ni := item.(*nodeCacheItem)
			nodeBytes, nerr := ni.n.MarshalBinary()
			if nerr != nil {
				continue
			}
			bytes = append(bytes, []byte{'N'}...)
			bytes = append(bytes, nodeBytes...)

			ch <- bytes
		}
	}()

	enc := codec.NewEncoder(w, cbor.Handle)
	defer enc.Release()
	if err = enc.Encode(ch); err != nil {
		return errors.Wrap(err, "urkel/db/lru: failed to serialize cache")
	}

	return nil
}

func (d *lruNodeDB) load() error {
	f, err := os.Open(d.fname)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing wrong if we don't have a cache file yet.
			return nil
		}
		return errors.Wrap(err, "urkel/db/lru: failed to open cache file")
	}
	defer f.Close()

	r := bufio.NewReader(f)
	ch := make(chan []byte)
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		for v := range ch {
			if v[0] != 'K' || len(v) < 1+hash.Size+1 {
				continue
			}

			// Deserialize key.
			var key hash.Hash
			kerr := key.UnmarshalBinary(v[1 : 1+hash.Size])
			if kerr != nil {
				continue
			}

			switch v[1+hash.Size] {
			case 'N':
				// Deserialize node.
				node, nerr := urkel.UnmarshalBinary(v[1+hash.Size+1:])
				if nerr != nil {
					continue
				}
				_ = d.putLocked(key, &nodeCacheItem{n: node})
			default:
				continue
			}
		}
	}()

	dec := codec.NewDecoder(r, cbor.Handle)
	defer dec.Release()
	err = dec.Decode(&ch)
	close(ch)
	<-doneCh

	if err != nil && err != io.EOF {
		return errors.Wrap(err, "failed to deserialize cache")
	}

	return nil
}

func (d *lruNodeDB) putLocked(id hash.Hash, item interface{}) error {
	return d.items.Put(id, item)
}

func (d *lruNodeDB) getLocked(id hash.Hash) (interface{}, error) {
	item, found := d.items.Get(id)
	if !found {
		return nil, api.ErrNodeNotFound
	}

	return item, nil
}

type memoryBatch struct {
	api.BaseBatch

	db *lruNodeDB

	ops []func() error
}

func (d *lruNodeDB) NewBatch() api.Batch {
	return &memoryBatch{
		db: d,
	}
}

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth uint8, subtreeRoot *urkel.Pointer) api.Subtree {
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

func (s *memorySubtree) PutNode(depth uint8, ptr *urkel.Pointer) error {
	// We must use the unchecked version here as the node has not yet been
	// committed so it is still considered dirty even though the hash has
	// already been updated.
	node := ptr.Node.ExtractUnchecked()
	s.batch.ops = append(s.batch.ops, func() error {
		return s.batch.db.putLocked(node.GetHash(), &nodeCacheItem{n: node})
	})
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth uint8, ptr *urkel.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
