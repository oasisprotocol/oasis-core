package murkdb

import (
	"errors"
	"sync"
	"unsafe"

	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/sys/unix"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
)

var (
	// bktMeta is the name of the bucket holding the general metadata.
	bktMeta = []byte("M")
	// bktIndexOfRoots is the name of the bucket holding the index of roots.
	bktIndexOfRoots = []byte("R")
	// bktFreePages is the name of the bucket holding the index of free pages.
	bktIndexOfFreePages = []byte("F")

	keyMetaInfo = []byte("info")
)

// metaInfoSize is the size of the metaInfo structure.
const metaInfoSize = int(unsafe.Sizeof(metaInfo{}))

// metaInfoSize is the size of the metaInfo structure.
const rootInfoSize = int(unsafe.Sizeof(rootInfo{}))

type metaInfo struct {
	// lastPageID is the ID of the last page.
	lastPageID uint64
}

type rootInfo struct {
	// offset is a type/offset pointing to the root node.
	offset uint64
}

type metaDB struct {
	// db is the BoltDB store used to hold metadata.
	db *bolt.DB
	// tree is the treeDB instance.
	tree *treeDB

	currentMeta metaInfo

	writeLock   sync.Mutex
	pendingMeta metaInfo
}

func openMetaDB(filename string, tree *treeDB) (*metaDB, error) {
	m := &metaDB{tree: tree}

	var err error
	if m.db, err = bolt.Open(filename, fileMode, nil); err != nil {
		return nil, err
	}

	// Read current metadata.
	if err = m.reload(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *metaDB) reload() error {
	m.writeLock.Lock()
	defer m.writeLock.Unlock()

	return m.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktMeta)
		if bkt == nil {
			// No metadata yet, treat as default-initialized metadata.
			return nil
		}

		panic("murkdb: metadata load not yet implemented")
	})
}

func (m *metaDB) openBatch() {
	m.writeLock.Lock()
	m.pendingMeta = m.currentMeta
}

// NOTE: writeLock must be held while calling this method.
func (m *metaDB) commitBatchLocked(root hash.Hash, offset uint64) error {
	defer func() {
		m.pendingMeta = m.currentMeta
		m.writeLock.Unlock()
	}()

	// Ensure tree data is written to disk.
	if err := unix.Fdatasync(int(m.tree.file.Fd())); err != nil {
		return err
	}

	// Remap if we appended some pages.
	minSize := int(m.pendingMeta.lastPageID+1) * m.tree.pageSize
	if minSize >= m.tree.dataSize {
		if err := m.tree.remap(minSize); err != nil {
			return err
		}
	}

	// Persist metadata.
	err := m.db.Update(func(tx *bolt.Tx) error {
		// Update index of roots.
		bkt, err := tx.CreateBucketIfNotExists(bktIndexOfRoots)
		if err != nil {
			return err
		}

		ri := rootInfo{offset: offset}
		rbuf := (*[rootInfoSize]byte)(unsafe.Pointer(&ri))[:rootInfoSize]
		if err = bkt.Put(root[:], rbuf); err != nil {
			return err
		}

		// Update meta info.
		if bkt, err = tx.CreateBucketIfNotExists(bktMeta); err != nil {
			return err
		}

		mbuf := (*[metaInfoSize]byte)(unsafe.Pointer(&m.pendingMeta))[:metaInfoSize]
		if err = bkt.Put(keyMetaInfo, mbuf); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Update cached metadata.
	m.currentMeta = m.pendingMeta

	return nil
}

// NOTE: writeLock must be held while calling this method.
func (m *metaDB) rollbackBatchLocked() {
	m.pendingMeta = m.currentMeta
	m.writeLock.Unlock()
}

// NOTE: writeLock must be held while calling this method.
func (m *metaDB) allocateLocked(count int) (*page, error) {
	// Allocate a temporary buffer for the page.
	var buf []byte
	if count == 1 {
		// TODO: Allocate page buffer from the pool.
		// buf = m.pagePool.Get().([]byte)
		buf = make([]byte, m.tree.pageSize)
	} else {
		buf = make([]byte, count*m.tree.pageSize)
	}
	p := (*page)(unsafe.Pointer(&buf[0]))
	p.overflow = uint32(count - 1)

	// TODO: Use pages from the free pages index if available.

	// Take from the end if nothing else is available.
	p.id = m.pendingMeta.lastPageID
	m.pendingMeta.lastPageID += uint64(count)

	return p, nil
}

func (m *metaDB) getRoot(root hash.Hash) (ri *rootInfo, err error) {
	// TODO: Cache roots?

	err = m.db.View(func(tx *bolt.Tx) error {
		// Open the index of roots bucket. If it doesn't exist treat this as a
		// root not found error.
		bkt := tx.Bucket(bktIndexOfRoots)
		if bkt == nil {
			return errors.New("murkdb: root not found")
		}

		buf := bkt.Get(root[:])
		if buf == nil {
			return api.ErrRootNotFound
		}

		tmp := (*rootInfo)(unsafe.Pointer(&buf[0]))
		ri = &rootInfo{}
		*ri = *tmp

		return nil
	})
	return
}

func (m *metaDB) close() error {
	m.writeLock.Lock()
	defer m.writeLock.Unlock()

	return m.db.Close()
}
