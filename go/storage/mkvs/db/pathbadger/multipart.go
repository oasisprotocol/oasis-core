package pathbadger

import (
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	// multipartVersionNone is the value used for the multipart version in metadata when no
	// multipart restore is in progress.
	multipartVersionNone uint64 = 0
)

// multipartMeta contains per-root-type metadata of an ongoing multipart insert operation.
type multipartMeta struct {
	seqNo     uint16
	root      *api.TypedHash
	lastIndex *atomic.Uint32

	// mpLock is the lock that prevents multiple batches from being inserted concurrently. This is
	// currently needed because otherwise it would result in corruptions due to merge conflicts.
	mpLock sync.Mutex
}

// Implements api.NodeDB.
func (d *badgerNodeDB) StartMultipartInsert(version uint64) error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if version == multipartVersionNone {
		return api.ErrInvalidMultipartVersion
	}

	if d.multipartVersion != multipartVersionNone {
		if d.multipartVersion != version {
			return api.ErrMultipartInProgress
		}
		// Multipart already initialized at the same version, so this was probably called e.g. as
		// part of a further checkpoint restore.
		return nil
	}

	tx := d.db.NewTransactionAt(tsMetadata, true)
	defer tx.Discard()

	// Reserve sequence numbers for all root types.
	multiMeta := make(map[uint8]*multipartMeta)
	for _, rootType := range api.RootTypes() {
		seqNo, err := d.meta.reserveRootSeqNo(version, uint8(rootType))
		if err != nil {
			return err
		}

		lastIndex := new(atomic.Uint32)
		lastIndex.Store(indexRootNode)

		multiMeta[uint8(rootType)] = &multipartMeta{
			seqNo:     seqNo,
			lastIndex: lastIndex,
		}
	}

	d.meta.setMultipart(version, multiMeta)
	d.meta.commit(tx)

	d.multipartVersion = version
	d.multipartMeta = multiMeta

	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) AbortMultipartInsert() error {
	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	return d.cleanMultipartLocked(true)
}

// Assumes metaUpdateLock is held when called.
func (d *badgerNodeDB) cleanMultipartLocked(removeNodes bool) error {
	var (
		version uint64
		seqs    map[uint8]uint16
	)
	if d.multipartVersion != multipartVersionNone {
		version = d.multipartVersion
		seqs = make(map[uint8]uint16)
		for t, m := range d.multipartMeta {
			seqs[t] = m.seqNo
		}
	} else {
		version, seqs = d.meta.getMultipart()
	}
	if version == multipartVersionNone {
		// No multipart in progress, but it's not an error to call in a situation like this.
		return nil
	}

	txn := d.db.NewTransactionAt(tsMetadata, false)
	defer txn.Discard()

	opts := badger.DefaultIteratorOptions
	opts.Prefix = multipartRestoreNodeLogKeyFmt.Encode()
	it := txn.NewIterator(opts)
	defer it.Close()

	batch := d.db.NewWriteBatchAt(versionToTs(version))
	defer batch.Cancel()

	var logged bool
	for it.Rewind(); it.Valid(); it.Next() {
		key := it.Item().Key()
		if removeNodes {
			if !logged {
				d.logger.Info("removing some nodes from a multipart restore")
				logged = true
			}
			var (
				rootType uint8
				dbKey    []byte
			)
			if !multipartRestoreNodeLogKeyFmt.Decode(key, &rootType, &dbKey) {
				panic("mkvs/pathbadger: corrupted key")
			}

			if seqNo := seqs[rootType]; seqNo == 0 {
				if err := batch.Delete(finalizedNodeKeyFmt.Encode(rootType, dbKey)); err != nil {
					return err
				}
			} else {
				if err := batch.DeleteAt(pendingNodeKeyFmt.Encode(d.multipartVersion, rootType, seqNo, dbKey), tsMetadata); err != nil {
					return err
				}
			}
		}
		if err := batch.DeleteAt(key, tsMetadata); err != nil {
			return err
		}
	}

	// Flush batch first. If anything fails, having corrupt multipart info in d.meta shouldn't hurt
	// us next run.
	if err := batch.Flush(); err != nil {
		return err
	}

	metaTx := d.db.NewTransactionAt(tsMetadata, true)
	defer metaTx.Discard()
	d.meta.setMultipart(0, nil)
	d.meta.commit(metaTx)

	d.multipartVersion = multipartVersionNone
	d.multipartMeta = nil
	return nil
}

func (ba *badgerBatch) multipartMergeWithExisting(dbKey []byte, ptr *node.Pointer) error {
	if dbKey == nil {
		return nil
	}

	item, err := ba.readTxn.Get(dbKey)
	switch {
	case err == nil:
	case err == badger.ErrKeyNotFound:
		return nil
	default:
		return err
	}

	// If item already exists, we may need to merge both nodes.
	intNode, ok := ptr.Node.(*node.InternalNode)
	if !ok {
		return nil
	}

	var n node.Node
	if err = item.Value(func(val []byte) error {
		var vErr error
		n, vErr = nodeFromDb(val)
		return vErr
	}); err != nil {
		return err
	}

	// Merge both nodes in case they are internal.
	existingNode, ok := n.(*node.InternalNode)
	if !ok {
		return nil
	}

	// Merge any partial pointers.
	for _, p := range []struct {
		existing *node.Pointer
		new      *node.Pointer
	}{
		{existingNode.Left, intNode.Left},
		{existingNode.Right, intNode.Right},
		{existingNode.LeafNode, intNode.LeafNode},
	} {
		if p.new == nil || p.existing == nil {
			continue
		}
		if !p.existing.Hash.Equal(&p.new.Hash) { //nolint: gosec
			continue
		}
		if p.existing.DBInternal == nil || p.new.DBInternal != nil {
			continue
		}
		p.new.DBInternal = p.existing.DBInternal
	}

	return nil
}
