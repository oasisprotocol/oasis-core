// Package pathbadger provides a Badger-backed node database that uses trie paths as keys.
package pathbadger

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// dbVersion is the internal database version. We start with 6 to make sure this is distinct from
// the older badger backend which uses a database version of 5.
const dbVersion = 6

// New creates a new BadgerDB-backed node database that uses trie paths as keys.
func New(cfg *api.Config) (api.NodeDB, error) {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/pathbadger"),
		namespace:        cfg.Namespace,
		readOnly:         cfg.ReadOnly,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}
	opts := commonConfigToBadgerOptions(cfg, db.logger)

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return nil, fmt.Errorf("mkvs/pathbadger: failed to open database: %w", err)
	}

	// Make sure that we can discard any deleted/invalid metadata.
	db.db.SetDiscardTs(tsMetadata)

	// Initialize database metadata.
	if err = db.initMetadata(); err != nil {
		_ = db.db.Close()
		return nil, fmt.Errorf("mkvs/pathbadger: failed to initialize metadata: %w", err)
	}

	// Update discard timestamp based on earliest version.
	earliestVersion := db.meta.getEarliestVersion()
	db.db.SetDiscardTs(versionToTs(earliestVersion))

	// Cleanup any multipart restore remnants, since they can't be used anymore.
	if err = db.cleanMultipartLocked(true); err != nil {
		_ = db.db.Close()
		return nil, fmt.Errorf("mkvs/pathbadger: failed to clean leftovers from multipart restore: %w", err)
	}

	db.gc = cmnBadger.NewGCWorker(db.logger, db.db)
	db.gc.Start()

	// Setting a discard timestamp of the BadgerDB is not persistent and is currently
	// only done during the prune operation.
	//
	// Imagine a scenario where during the previous boot of the BadgerDB, data was successfully pruned,
	// but not yet compacted. Then the NodeDB is restarted, only this time with pruning disabled.
	// Unless setting discard timestamp to the earliest version manually, the data stored for the
	// already pruned versions may never be compacted, resulting in redundant disk usage.
	if discardTs := versionToTs(db.GetEarliestVersion()) - 1; discardTs > tsMetadata {
		db.db.SetDiscardTs(discardTs)
	}

	return db, nil
}

type badgerNodeDB struct {
	logger *logging.Logger

	namespace common.Namespace

	readOnly         bool
	discardWriteLogs bool

	multipartVersion uint64
	multipartMeta    map[uint8]*multipartMeta

	db *badger.DB
	gc *cmnBadger.GCWorker

	// metaUpdateLock must be held at any point where data at tsMetadata is read and updated. This
	// is required because all metadata updates happen at the same timestamp and as such conflicts
	// cannot be detected.
	metaUpdateLock sync.Mutex
	meta           metadata

	closeOnce sync.Once
}

func (d *badgerNodeDB) initMetadata() error {
	tx := d.db.NewTransactionAt(tsMetadata, true)
	defer tx.Discard()

	// Ensure that no legacy metadata exists to prevent corrupting a database created using the old
	// badger backend.
	if _, err := tx.Get([]byte{0x04}); err != badger.ErrKeyNotFound {
		return fmt.Errorf("incompatible database version")
	}

	// Load metadata.
	item, err := tx.Get(metadataKeyFmt.Encode())
	switch err {
	case nil:
		// Metadata already exists, just load it and verify that it is
		// compatible with what we have here.
		err = item.Value(func(data []byte) error {
			return cbor.UnmarshalTrusted(data, &d.meta.value)
		})
		if err != nil {
			return err
		}

		if d.meta.value.Version != dbVersion {
			return fmt.Errorf("incompatible database version (expected: %d got: %d)",
				dbVersion,
				d.meta.value.Version,
			)
		}
		if !d.meta.value.Namespace.Equal(&d.namespace) {
			return fmt.Errorf("incompatible namespace (expected: %s got: %s)",
				d.namespace,
				d.meta.value.Namespace,
			)
		}
		return nil
	case badger.ErrKeyNotFound:
	default:
		return err
	}

	// No metadata exists, create some.
	d.meta.value.Version = dbVersion
	d.meta.value.Namespace = d.namespace
	d.meta.commit(tx)

	return nil
}

func (d *badgerNodeDB) sanityCheckNamespace(ns *common.Namespace) error {
	if !ns.Equal(&d.namespace) {
		return api.ErrBadNamespace
	}
	return nil
}

func (d *badgerNodeDB) checkRootExists(tx *badger.Txn, root node.Root) error {
	rootHash := api.TypedHashFromRoot(root)
	if _, err := tx.Get(rootNodeKeyFmt.Encode(root.Version, &rootHash)); err != nil {
		switch err {
		case badger.ErrKeyNotFound:
			return api.ErrRootNotFound
		default:
			d.logger.Error("failed to check root existence",
				"err", err,
			)
			return fmt.Errorf("mkvs/pathbadger: failed to check root existence while getting node from backing store: %w", err)
		}
	}
	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) GetLatestVersion() (uint64, bool) {
	return d.meta.getLastFinalizedVersion()
}

// Implements api.NodeDB.
func (d *badgerNodeDB) GetEarliestVersion() uint64 {
	return d.meta.getEarliestVersion()
}

// Implements api.NodeDB.
func (d *badgerNodeDB) GetRootsForVersion(version uint64) ([]node.Root, error) {
	// If the version is earlier than the earliest version, we don't have the roots.
	if version < d.meta.getEarliestVersion() {
		return nil, nil
	}

	tx := d.db.NewTransactionAt(versionToTs(version), false)
	defer tx.Discard()

	prefix := rootNodeKeyFmt.Encode(version)
	it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	var roots []node.Root
	for it.Rewind(); it.Valid(); it.Next() {
		var (
			v        uint64
			rootHash api.TypedHash
		)
		if !rootNodeKeyFmt.Decode(it.Item().Key(), &v, &rootHash) {
			panic("mkvs/pathbadger: corrupted key")
		}

		roots = append(roots, node.Root{
			Namespace: d.namespace,
			Version:   version,
			Type:      rootHash.Type(),
			Hash:      rootHash.Hash(),
		})
	}

	return roots, nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) HasRoot(root node.Root) bool {
	if err := d.sanityCheckNamespace(&root.Namespace); err != nil {
		return false
	}

	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	// If the version is earlier than the earliest version, we don't have the root.
	if root.Version < d.meta.getEarliestVersion() {
		return false
	}

	tx := d.db.NewTransactionAt(versionToTs(root.Version), false)
	defer tx.Discard()

	if err := d.checkRootExists(tx, root); err != nil {
		return false
	}

	return true
}

// Implements api.NodeDB.
func (d *badgerNodeDB) Finalize(roots []node.Root) error { // nolint: gocyclo
	if d.readOnly {
		return api.ErrReadOnly
	}

	if len(roots) == 0 {
		return fmt.Errorf("mkvs/pathbadger: need at least one root to finalize")
	}
	version := roots[0].Version

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	// Validate multipart version.
	if d.multipartVersion != multipartVersionNone && d.multipartVersion != version {
		return api.ErrInvalidMultipartVersion
	}
	// Validate version.
	if lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion(); exists {
		// Make sure that this version has not yet been finalized.
		if version <= lastFinalizedVersion {
			return api.ErrAlreadyFinalized
		}
		// Make sure that the previous version has been finalized (if we are not restoring).
		if d.multipartVersion == multipartVersionNone && lastFinalizedVersion+1 != version {
			return api.ErrNotFinalized
		}
	}

	// Ensure that all roots are valid and only one root per type is finalized.
	typeCheck := make(map[node.RootType]struct{})
	finalizedRoots := make(map[api.TypedHash]struct{})
	for _, root := range roots {
		if root.Version != version {
			return fmt.Errorf("mkvs/pathbadger: roots to finalize don't have matching versions")
		}
		h := api.TypedHashFromRoot(root)
		finalizedRoots[h] = struct{}{}

		if _, ok := typeCheck[root.Type]; ok {
			return fmt.Errorf("mkvs/pathbadger: only one root of type '%s' may be finalized", root.Type)
		}
		typeCheck[root.Type] = struct{}{}
	}

	// Batch collects removals and copies at the version timestamp.
	batch := d.db.NewWriteBatchAt(versionToTs(version))
	defer batch.Cancel()
	// Batch meta collects removals at the tsMeta timestamp.
	batchMeta := d.db.NewWriteBatchAt(tsMetadata)
	defer batchMeta.Cancel()
	// Transaction is used to read at the version timestamp.
	tx := d.db.NewTransactionAt(versionToTs(version), true)
	defer tx.Discard()

	// Ensure that all roots are valid and only one root per type is finalized.
	var nonEmptyFinalizedRoots, nonEmptyVisitedRoots int
	for _, root := range roots {
		if root.Hash.IsEmpty() {
			continue
		}
		if err := d.checkRootExists(tx, root); err != nil {
			return err
		}
		nonEmptyFinalizedRoots++
	}

	// Traverse all known roots for the version.
	rootsPrefix := rootNodeKeyFmt.Encode(version)
	rootIt := tx.NewIterator(badger.IteratorOptions{Prefix: rootsPrefix})
	defer rootIt.Close()

	var removeMetaKeys [][]byte
	finalizedSeqNos := make(map[byte]uint16)
	maybeLoneNodes := make(map[byte]map[string]struct{})
	notLoneNodes := make(map[byte]map[string]struct{})

	for rootIt.Rewind(); rootIt.Valid(); rootIt.Next() {
		var (
			v        uint64
			rootHash api.TypedHash
		)
		if !rootNodeKeyFmt.Decode(rootIt.Item().Key(), &v, &rootHash) {
			panic("mkvs/pathbadger: corrupted key")
		}

		// Check sequence number for the root.
		seqNo, exists := d.meta.getPendingRootSeqNo(version, rootHash)
		if !exists {
			return fmt.Errorf("mkvs/pathbadger: pending root sequence number not found for root '%s'", rootHash)
		}

		// Load set of updated nodes.
		var updatedNodes []updatedNode
		rootUpdatedNodesKey := rootUpdatedNodesKeyFmt.Encode(version, &rootHash)
		item, err := tx.Get(rootUpdatedNodesKey)
		switch err {
		case nil:
			// We have some updated nodes.
			err = item.Value(func(data []byte) error {
				return cbor.UnmarshalTrusted(data, &updatedNodes)
			})
			if err != nil {
				return fmt.Errorf("mkvs/pathbadger: corrupted updated nodes index: %w", err)
			}

			removeMetaKeys = append(removeMetaKeys, rootUpdatedNodesKey)
		case badger.ErrKeyNotFound:
			// No updated nodes.
		default:
			return fmt.Errorf("mkvs/pathbadger: failed to fetch updated nodes index: %w", err)
		}

		rht := byte(rootHash.Type())
		if maybeLoneNodes[rht] == nil {
			maybeLoneNodes[rht] = make(map[string]struct{})
		}
		if notLoneNodes[rht] == nil {
			notLoneNodes[rht] = make(map[string]struct{})
		}

		// Determine whether the root has been finalized.
		switch _, isFinalized := finalizedRoots[rootHash]; isFinalized {
		case true:
			// Root has been finalized.
			for _, un := range updatedNodes {
				if un.Removed {
					maybeLoneNodes[rht][string(un.Key)] = struct{}{}
				} else {
					notLoneNodes[rht][string(un.Key)] = struct{}{}
				}
			}

			finalizedSeqNos[rht] = seqNo
			if h := rootHash.Hash(); !h.IsEmpty() {
				nonEmptyVisitedRoots++
			}
		case false:
			// Remove any non-finalized roots. It is safe to remove these nodes as Badger's version
			// control will make sure they are not removed if they are resurrected in any later
			// version as long as we make sure that these nodes are not shared with any finalized
			// roots added in the same version.
			for _, un := range updatedNodes {
				if un.Removed {
					continue // Ignore removed nodes for non-finalized roots.
				}
				if seqNo > 0 {
					continue // All nodes with higher seqNo will be cleared anyway.
				}

				maybeLoneNodes[rht][string(un.Key)] = struct{}{}
			}

			// Remove write logs for the non-finalized root.
			if !d.discardWriteLogs {
				if err = func() error {
					rootWriteLogsPrefix := writeLogKeyFmt.Encode(version, &rootHash)
					wit := tx.NewIterator(badger.IteratorOptions{Prefix: rootWriteLogsPrefix})
					defer wit.Close()

					for wit.Rewind(); wit.Valid(); wit.Next() {
						if err = batchMeta.Delete(wit.Item().KeyCopy(nil)); err != nil {
							return err
						}
					}
					return nil
				}(); err != nil {
					return err
				}
			}
		}
	}

	rootIt.Close()

	// Sanity check that all finalized roots were visited.
	if nonEmptyFinalizedRoots != nonEmptyVisitedRoots {
		return fmt.Errorf("mkvs/pathbadger: not all finalized roots were visited (db corruption?)")
	}

	// Copy over any updated nodes for finalized roots with non-zero sequence numbers.
	for rht, nodes := range notLoneNodes {
		seqNo := finalizedSeqNos[rht]
		if seqNo == 0 {
			continue // Already in the right place.
		}

		for k := range nodes {
			// Fetch pending node value. We will remove it later.
			item, err := tx.Get(pendingNodeKeyFmt.Encode(version, rht, seqNo, []byte(k)))
			if err != nil {
				return fmt.Errorf("mkvs/pathbadger: failed to copy node: %w", err)
			}
			var value []byte
			err = item.Value(func(data []byte) error {
				value = append([]byte{}, data...) // Must copy to queue in batch.
				return nil
			})
			if err != nil {
				return fmt.Errorf("mkvs/pathbadger: failed to copy node: %w", err)
			}

			// Copy over to new location.
			if err := batch.Set(finalizedNodeKeyFmt.Encode(rht, []byte(k)), value); err != nil {
				return fmt.Errorf("mkvs/pathbadger: failed to copy node: %w", err)
			}
		}
	}

	// All removals should be done at the end so in case finalization is interrupted, we can recover
	// by simply redoing finalization. Flush batches here to ensure all node copying has been
	// committed.
	if err := batch.Flush(); err != nil {
		return err
	}
	if err := batchMeta.Flush(); err != nil {
		return err
	}
	batch = d.db.NewWriteBatchAt(versionToTs(version))
	defer batch.Cancel()
	batchMeta = d.db.NewWriteBatchAt(tsMetadata)
	defer batchMeta.Cancel()

	// Remove any lone nodes. This can be retried.
	for rht, nodes := range maybeLoneNodes {
		for k := range nodes {
			if _, isNotLone := notLoneNodes[rht][k]; isNotLone {
				continue
			}

			if err := batch.Delete(finalizedNodeKeyFmt.Encode(rht, []byte(k))); err != nil {
				return fmt.Errorf("mkvs/pathbadger: failed to delete lone node: %w", err)
			}
		}
	}

	// Remove any queued keys. This should happen before removing pending nodes so in case we fail
	// the worst that can happen is that some pending nodes are left over and will be removed during
	// next finalization.
	for _, key := range removeMetaKeys {
		if err := batchMeta.Delete(key); err != nil {
			return fmt.Errorf("mkvs/pathbadger: failed to delete key: %w", err)
		}
	}

	// Remove all temporary nodes for non-zero sequence numbers. Relevant ones have been copied.
	pendingPrefix := pendingNodeKeyFmt.Encode(version)
	pendingIt := tx.NewIterator(badger.IteratorOptions{Prefix: pendingPrefix})
	defer pendingIt.Close()

	for pendingIt.Rewind(); pendingIt.Valid(); pendingIt.Next() {
		if err := batchMeta.Delete(pendingIt.Item().KeyCopy(nil)); err != nil {
			return fmt.Errorf("mkvs/pathbadger: failed to delete pending node: %w", err)
		}
	}

	pendingIt.Close()

	// Commit batches. If this fails, deletion will be redone.
	if err := batch.Flush(); err != nil {
		return err
	}
	if err := batchMeta.Flush(); err != nil {
		return err
	}

	// Update last finalized version.
	d.meta.setLastFinalizedVersion(version)
	d.meta.commit(tx)

	// Clean multipart metadata if there is any.
	if d.multipartVersion != multipartVersionNone {
		if err := d.cleanMultipartLocked(false); err != nil {
			return err
		}
	}
	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) Prune(version uint64) error {
	if d.readOnly {
		return api.ErrReadOnly
	}

	d.metaUpdateLock.Lock()
	defer d.metaUpdateLock.Unlock()

	if d.multipartVersion != multipartVersionNone {
		return api.ErrMultipartInProgress
	}

	// Make sure that the version that we try to prune has been finalized.
	lastFinalizedVersion, exists := d.meta.getLastFinalizedVersion()
	if !exists || lastFinalizedVersion < version {
		return api.ErrNotFinalized
	}
	// Make sure that the version that we are trying to prune is the earliest version.
	if version != d.meta.getEarliestVersion() {
		return api.ErrNotEarliest
	}
	// Make sure that the version that we are trying to prune is not the only finalized version.
	if version == lastFinalizedVersion {
		return api.ErrCannotPruneLatestVersion
	}

	// Remove all roots in version.
	batch := d.db.NewWriteBatchAt(versionToTs(version))
	defer batch.Cancel()
	batchMeta := d.db.NewWriteBatchAt(tsMetadata)
	defer batchMeta.Cancel()
	tx := d.db.NewTransactionAt(versionToTs(version), true)
	defer tx.Discard()

	// Delete data for all root types that cannot have children.
	for _, rootType := range api.RootTypesWithPolicy(func(p *api.RootPolicy) bool { return p.NoChildRoots }) {
		// Delete all finalized nodes.
		wtx := d.db.NewTransactionAt(versionToTs(version), false)
		defer wtx.Discard()

		prefix := finalizedNodeKeyFmt.Encode(byte(rootType))
		it := wtx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			if err := batch.Delete(it.Item().KeyCopy(nil)); err != nil {
				return err
			}
		}

		it.Close()

		// Delete all root nodes of this type (there should be only one per type).
		prefix = rootNodeKeyFmt.Encode(version)
		it = wtx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			var (
				v        uint64
				rootHash api.TypedHash
			)
			if !rootNodeKeyFmt.Decode(it.Item().Key(), &v, &rootHash) {
				panic("mkvs/pathbadger: corrupted key")
			}
			if rootHash.Type() != rootType {
				continue
			}

			if err := batch.Delete(it.Item().KeyCopy(nil)); err != nil {
				return err
			}
		}

		it.Close()
		wtx.Discard()
	}

	// Prune all write logs in version.
	if !d.discardWriteLogs {
		wtx := d.db.NewTransactionAt(tsMetadata, false)
		defer wtx.Discard()

		prefix := writeLogKeyFmt.Encode(version)
		it := wtx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			if err := batchMeta.Delete(it.Item().KeyCopy(nil)); err != nil {
				return err
			}
		}

		it.Close()
		wtx.Discard()
	}

	// Commit batch.
	if err := batch.Flush(); err != nil {
		return fmt.Errorf("mkvs/pathbadger: failed to flush batch: %w", err)
	}
	if err := batchMeta.Flush(); err != nil {
		return fmt.Errorf("mkvs/pathbadger: failed to flush batch: %w", err)
	}

	// Update metadata.
	d.meta.setEarliestVersion(version + 1)
	d.meta.commit(tx)

	// Discard everything invalidated at or below the _new_ earliest version. E.g. there is no need
	// to keep around any keys that were removed at `version + 1`.
	d.db.SetDiscardTs(versionToTs(version + 1))

	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) NewBatch(oldRoot node.Root, version uint64, chunk bool) (api.Batch, error) {
	// WARNING: There is a maximum batch size and maximum batch entry count.
	// Both of these things are derived from the MaxTableSize option.
	//
	// The size limit also applies to normal transactions, so the "right"
	// thing to do would be to either crank up MaxTableSize or maybe split
	// the transaction out.

	if d.readOnly {
		return nil, api.ErrReadOnly
	}

	if version != oldRoot.Version && version != oldRoot.Version+1 {
		return nil, api.ErrRootMustFollowOld
	}

	// Ensure old root exists and the batch is compliant with the policy.
	tx := d.db.NewTransactionAt(versionToTs(oldRoot.Version), true)
	defer tx.Discard()

	if err := d.sanityCheckNamespace(&oldRoot.Namespace); err != nil {
		return nil, err
	}

	if !oldRoot.Hash.IsEmpty() {
		policy := api.PolicyForRoot(oldRoot)
		if policy == nil {
			return nil, fmt.Errorf("mkvs/pathbadger: unsupported root type '%s'", oldRoot.Type)
		}
		if policy.NoChildRoots {
			return nil, fmt.Errorf("mkvs/pathbadger: roots of type '%s' cannot have child roots", oldRoot.Type)
		}
		if oldRoot.Version == version {
			return nil, fmt.Errorf("mkvs/pathbadger: child roots in the same version not supported")
		}
		if err := d.checkRootExists(tx, oldRoot); err != nil {
			return nil, err
		}
	}

	d.metaUpdateLock.Lock()
	var ok bool
	defer func() {
		if !ok {
			d.metaUpdateLock.Unlock()
		}
	}()

	if d.multipartVersion != multipartVersionNone && d.multipartVersion != version {
		return nil, api.ErrInvalidMultipartVersion
	}
	if chunk != (d.multipartVersion != multipartVersionNone) {
		return nil, api.ErrMultipartInProgress
	}

	var (
		readTxn   *badger.Txn
		seqNo     uint16
		lastIndex *atomic.Uint32
		mpLock    *sync.Mutex
	)
	if d.multipartVersion != multipartVersionNone {
		readTxn = d.db.NewTransactionAt(versionToTs(version), false)
		multiMeta := d.multipartMeta[uint8(oldRoot.Type)]
		// Reuse the same seqNo for all multipart batches that was already reserved.
		seqNo = multiMeta.seqNo
		// Reuse the same index for all multipart batches.
		lastIndex = multiMeta.lastIndex
		// We currently only allow a single multipart batch concurrently.
		mpLock = &multiMeta.mpLock
	} else {
		// Reserve a sequence number for the batch.
		var err error
		seqNo, err = d.meta.reserveRootSeqNo(version, uint8(oldRoot.Type))
		if err != nil {
			return nil, err
		}
		d.meta.commit(tx)
		// Start a fresh index.
		lastIndex = new(atomic.Uint32)
		lastIndex.Store(indexRootNode)
	}

	ok = true
	d.metaUpdateLock.Unlock()
	if mpLock != nil {
		mpLock.Lock()
	}

	return &badgerBatch{
		db:        d,
		bat:       d.db.NewWriteBatchAt(versionToTs(version)),
		batMeta:   d.db.NewWriteBatchAt(tsMetadata),
		readTxn:   readTxn,
		oldRoot:   oldRoot,
		chunk:     chunk,
		version:   version,
		seqNo:     seqNo,
		lastIndex: lastIndex,
		mpLock:    mpLock,
	}, nil
}

func (d *badgerNodeDB) Compact() error {
	d.logger.Info("compacting")

	if err := d.db.Flatten(1); err != nil {
		return fmt.Errorf("failed to flatten db: %w", err)
	}

	d.logger.Info("compaction completed")

	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) Size() (int64, error) {
	lsm, vlog := d.db.Size()
	return lsm + vlog, nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) Sync() error {
	return d.db.Sync()
}

// Implements api.NodeDB.
func (d *badgerNodeDB) Close() {
	d.closeOnce.Do(func() {
		if d.gc != nil {
			d.gc.Stop()
		}

		if err := d.db.Close(); err != nil {
			d.logger.Error("close returned error",
				"err", err,
			)
		}
	})
}

type badgerBatch struct {
	api.BaseBatch

	db      *badgerNodeDB
	bat     *badger.WriteBatch
	batMeta *badger.WriteBatch

	// readTx is the read transaction used to check for node existence during
	// a multipart restore.
	readTxn *badger.Txn

	oldRoot   node.Root
	chunk     bool
	version   uint64
	seqNo     uint16
	lastIndex *atomic.Uint32

	writeLog     writelog.WriteLog
	annotations  writelog.Annotations
	updatedNodes []updatedNode
	newRootValue []byte

	mpLock *sync.Mutex
}

// Implements api.Batch.
func (ba *badgerBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/pathbadger: cannot put write log in chunk mode")
	}
	if ba.db.discardWriteLogs {
		return nil
	}
	if ba.writeLog != nil || ba.annotations != nil {
		return fmt.Errorf("mkvs/pathbadger: write log already set")
	}

	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

// Implements api.Batch.
func (ba *badgerBatch) RemoveNodes(nodes []*node.Pointer) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/pathbadger: cannot remove nodes in chunk mode")
	}

	for _, ptr := range nodes {
		iptr, ok := ptr.DBInternal.(*dbPtr)
		if !ok {
			continue // Skip nodes that were never persisted in the database.
		}
		if iptr.isRoot() {
			continue // Skip root nodes as those are tracked separately.
		}

		ba.updatedNodes = append(ba.updatedNodes, updatedNode{
			Removed: true,
			Key:     iptr.dbKey(),
		})
	}
	return nil
}

// Implements api.Batch.
func (ba *badgerBatch) Commit(root node.Root) error {
	ba.db.metaUpdateLock.Lock()
	defer ba.db.metaUpdateLock.Unlock()

	if err := ba.db.sanityCheckNamespace(&root.Namespace); err != nil {
		return err
	}
	if !root.Follows(&ba.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	// Make sure that the version that we try to commit into has not yet been finalized.
	lastFinalizedVersion, exists := ba.db.meta.getLastFinalizedVersion()
	if exists && lastFinalizedVersion >= root.Version {
		return api.ErrAlreadyFinalized
	}

	rootHash := api.TypedHashFromRoot(root)
	oldRootHash := api.TypedHashFromRoot(ba.oldRoot)

	if ba.db.multipartVersion != multipartVersionNone {
		if ba.db.multipartVersion != root.Version {
			return api.ErrInvalidMultipartVersion
		}

		multiMeta := ba.db.multipartMeta[uint8(rootHash.Type())]
		if multiMeta.root != nil && !multiMeta.root.Equal(&rootHash) {
			return fmt.Errorf("mkvs/pathbadger: cannot change multipart root for type '%s'", root.Type)
		}
		multiMeta.root = &rootHash
	}

	// Check if the root already exists.
	tx := ba.db.db.NewTransactionAt(versionToTs(root.Version), true)
	defer tx.Discard()

	// If we are not importing a chunk, check if the root already exists.
	if !ba.chunk {
		if err := ba.db.checkRootExists(tx, root); err == nil {
			// No need to do anything since if the hash matches, everything will be identical and we
			// would just be duplicating work.
			ba.Reset()
			return ba.BaseBatch.Commit(root)
		}
	}

	// Check if the root node was committed. In cases where the root has not actually changed, there
	// may be no root node and so we need to actually get it from the old version.
	if len(ba.newRootValue) == 0 && !root.Hash.IsEmpty() {
		if !rootHash.Equal(&oldRootHash) {
			// Should never happen unless something is seriously wrong.
			return fmt.Errorf("mkvs/pathbadger: no new root node, but new root hash not equal to old")
		}

		item, err := tx.Get(rootNodeKeyFmt.Encode(ba.oldRoot.Version, &oldRootHash))
		if err != nil {
			return fmt.Errorf("mkvs/pathbadger: failed to fetch old root node: %w", err)
		}

		err = item.Value(func(data []byte) error {
			ba.newRootValue = append([]byte{}, data...)
			return nil
		})
		if err != nil {
			return fmt.Errorf("mkvs/pathbadger: failed to copy old root node: %w", err)
		}
	}

	// Record sequence number for the pending (non-finalized) root. We need to commit this before
	// storing the root to make sure we can retry in case of a crash as otherwise the root can exist
	// but its sequence number is not known.
	if err := ba.db.meta.setPendingRootSeqNo(root.Version, rootHash, ba.seqNo); err != nil {
		return fmt.Errorf("mkvs/pathbadger: failed to set pending root seqno: %w", err)
	}
	ba.db.meta.commit(tx)

	if !ba.chunk {
		// Store updated nodes (only needed until the version is finalized).
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &rootHash)
		if err := ba.batMeta.Set(key, cbor.Marshal(ba.updatedNodes)); err != nil {
			return fmt.Errorf("mkvs/pathbadger: set returned error: %w", err)
		}

		// Store write log.
		if err := storeInternalWriteLog(ba.batMeta, oldRootHash, rootHash, root.Version, ba.writeLog, ba.annotations); err != nil {
			return err
		}
	}

	// Make sure root node update happens last so in case anything fails, we can retry.
	if err := ba.bat.Set(rootNodeKeyFmt.Encode(root.Version, &rootHash), ba.newRootValue); err != nil {
		return err
	}

	// Flush node updates.
	if err := ba.batMeta.Flush(); err != nil {
		return fmt.Errorf("mkvs/pathbadger: failed to flush batch: %w", err)
	}
	if err := ba.bat.Flush(); err != nil {
		return fmt.Errorf("mkvs/pathbadger: failed to flush batch: %w", err)
	}

	ba.Reset()
	return ba.BaseBatch.Commit(root)
}

// Implements api.Batch.
func (ba *badgerBatch) Reset() {
	ba.bat.Cancel()
	ba.batMeta.Cancel()

	if ba.readTxn != nil {
		ba.readTxn.Discard()
	}

	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil
	ba.newRootValue = nil

	if ba.mpLock != nil {
		ba.mpLock.Unlock()
		ba.mpLock = nil
	}
}
