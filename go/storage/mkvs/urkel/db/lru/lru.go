// Package lru provides a lossy LRU-cache based node database.
package lru

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"

	"github.com/oasislabs/go-codec/codec"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	lruCache "github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	urkel "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
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
	urkel.Node
}

func (nci *nodeCacheItem) Size() (size uint64) {
	// Add the size of the hash that is used as the node key.
	return nci.Node.Size() + hash.Size
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

func (d *lruNodeDB) GetNode(root urkel.Root, ptr *urkel.Pointer) (urkel.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel/db/lru: attempted to get invalid pointer from node database")
	}

	d.RLock()
	defer d.RUnlock()

	item, err := d.getLocked(ptr.Hash)
	if err != nil {
		return nil, err
	}

	return item.(*nodeCacheItem).Extract(), nil
}

func (d *lruNodeDB) GetWriteLog(ctx context.Context, startRoot urkel.Root, endRoot urkel.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}

	return nil, api.ErrWriteLogNotFound
}

func (d *lruNodeDB) GetCheckpoint(ctx context.Context, hash urkel.Root) (api.WriteLogIterator, error) {
	return nil, api.ErrWriteLogNotFound
}

func (d *lruNodeDB) HasRoot(root urkel.Root) bool {
	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	_, err := d.GetNode(root, &urkel.Pointer{
		Clean: true,
		Hash:  root.Hash,
	})
	return err != api.ErrNodeNotFound
}

func (d *lruNodeDB) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	return nil
}

func (d *lruNodeDB) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	return 0, nil
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
			nodeBytes, nerr := item.(*nodeCacheItem).MarshalBinary()
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
				_ = d.putLocked(key, &nodeCacheItem{node})
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

func (d *lruNodeDB) NewBatch(namespace common.Namespace, round uint64, oldRoot urkel.Root) api.Batch {
	return &memoryBatch{
		db: d,
	}
}

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth urkel.Depth, subtreeRoot *urkel.Pointer) api.Subtree {
	if subtree == nil {
		return &memorySubtree{batch: b}
	}
	return subtree
}

func (b *memoryBatch) PutWriteLog(writeLog writelog.WriteLog, logAnnotations writelog.WriteLogAnnotations) error {
	return nil
}

func (b *memoryBatch) RemoveNodes(nodes []urkel.Node) error {
	return nil
}

func (b *memoryBatch) Commit(root urkel.Root) error {
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

func (s *memorySubtree) PutNode(depth urkel.Depth, ptr *urkel.Pointer) error {
	// We must use the unchecked version here as the node has not yet been
	// committed so it is still considered dirty even though the hash has
	// already been updated.
	node := ptr.Node.ExtractUnchecked()
	s.batch.ops = append(s.batch.ops, func() error {
		return s.batch.db.putLocked(node.GetHash(), &nodeCacheItem{node})
	})
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth urkel.Depth, ptr *urkel.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
