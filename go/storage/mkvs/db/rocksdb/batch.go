//go:build rocksdb
// +build rocksdb

package rocksdb

import (
	"bytes"
	"fmt"

	"github.com/linxGnu/grocksdb"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

var _ api.Batch = (*rocksdbBatch)(nil)

type rocksdbBatch struct {
	api.BaseBatch

	db             *rocksdbNodeDB
	bat            *grocksdb.WriteBatch
	multipartNodes *grocksdb.WriteBatch

	oldRoot node.Root
	chunk   bool

	version  uint64
	rootType node.RootType

	writeLog     writelog.WriteLog
	annotations  writelog.Annotations
	updatedNodes []updatedNode
}

// Commit implements api.Batch.
func (ba *rocksdbBatch) Commit(root node.Root) error {
	defer ba.bat.Destroy()
	if ba.multipartNodes != nil {
		defer ba.multipartNodes.Destroy()
	}
	ba.db.metaUpdateLock.Lock()
	defer ba.db.metaUpdateLock.Unlock()

	if ba.db.multipartVersion != multipartVersionNone && ba.db.multipartVersion != root.Version {
		return api.ErrInvalidMultipartVersion
	}

	if err := ba.db.sanityCheckNamespace(root.Namespace); err != nil {
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

	rootsMeta, err := loadRootsMetadata(ba.db.db, ba.db.cfRoots, root.Version)
	if err != nil {
		return err
	}

	cf := ba.db.getColumnFamilyForRoot(root)
	rootHash := node.TypedHashFromRoot(root)
	ts := timestampFromVersion(root.Version)
	ba.bat.PutCFWithTS(cf, rootNodeKeyFmt.Encode(&rootHash), ts[:], []byte{})
	if ba.multipartNodes != nil {
		ba.multipartNodes.Put(multipartRestoreRootLogKeyFmt.Encode(&rootHash), []byte{})
	}

	if rootsMeta.Roots[rootHash] != nil {
		// Root already exists, no need to do anything since if the hash matches, everything will
		// be identical and we would just be duplicating work.
		//
		// If we are importing a chunk, there can be multiple commits for the same root.
		if !ba.chunk {
			ba.Reset()
			return ba.BaseBatch.Commit(root)
		}
	} else {
		// Create root with no derived roots.
		rootsMeta.Roots[rootHash] = []node.TypedHash{}
		rootsMeta.save(ba.bat)
	}

	if ba.chunk {
		// Skip most of metadata updates if we are just importing chunks.
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &rootHash)
		ba.bat.Put(key, cbor.Marshal([]updatedNode{}))
	} else {
		// Update the root link for the old root.
		oldRootHash := node.TypedHashFromRoot(ba.oldRoot)
		if !ba.oldRoot.Hash.IsEmpty() {
			if ba.oldRoot.Version < ba.db.meta.getEarliestVersion() && ba.oldRoot.Version != root.Version {
				return api.ErrPreviousVersionMismatch
			}

			var oldRootsMeta *rootsMetadata
			oldRootsMeta, err = loadRootsMetadata(ba.db.db, ba.db.cfRoots, ba.oldRoot.Version)
			if err != nil {
				return err
			}

			// Check if oldRootsMeta was updated in this batch. Since we don't see the
			// batch updates, until the batch is applied.
			wbIter := ba.bat.NewIterator()
			for {
				if !wbIter.Next() {
					break
				}
				rec := wbIter.Record()
				if bytes.Equal(rec.Key, rootsMetadataKeyFmt.Encode(ba.oldRoot.Version)) {
					if rec.Type == grocksdb.WriteBatchCFValueRecord {
						if err = cbor.Unmarshal(rec.Value, &oldRootsMeta); err != nil {
							panic(err)
						}
					}
				}
			}

			if _, ok := oldRootsMeta.Roots[oldRootHash]; !ok {
				return api.ErrRootNotFound
			}

			oldRootsMeta.Roots[oldRootHash] = append(oldRootsMeta.Roots[oldRootHash], rootHash)
			oldRootsMeta.save(ba.bat)
		}

		// Store updated nodes (only needed until the version is finalized).
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &rootHash)
		ba.bat.Put(key, cbor.Marshal(ba.updatedNodes))

		// Store write log.
		if ba.writeLog != nil && ba.annotations != nil {
			log := api.MakeHashedDBWriteLog(ba.writeLog, ba.annotations)
			bytes := cbor.Marshal(log)
			key := writeLogKeyFmt.Encode(root.Version, &rootHash, &oldRootHash)
			ba.bat.PutCFWithTS(cf, key, ts[:], bytes)
		}
	}

	// Flush node updates.
	if ba.multipartNodes != nil {
		if err = ba.db.db.Write(ba.db.defaultWriteOptions, ba.multipartNodes); err != nil {
			return fmt.Errorf("mkvs/rocksdb: failed to flush node log batch: %w", err)
		}
	}
	if err = ba.db.db.Write(ba.db.defaultWriteOptions, ba.bat); err != nil {
		return fmt.Errorf("mkvs/rocksdb: failed to flush batch: %w", err)
	}

	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil

	return ba.BaseBatch.Commit(root)
}

// MaybeStartSubtree implements api.Batch.
func (ba *rocksdbBatch) MaybeStartSubtree(subtree api.Subtree, _ node.Depth, _ *node.Pointer) api.Subtree {
	if subtree == nil {
		return &rocksdbSubtree{batch: ba}
	}
	return subtree
}

// PutWriteLog implements api.Batch.
func (ba *rocksdbBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/rocksdb: cannot put write log in chunk mode")
	}
	if ba.db.discardWriteLogs {
		return nil
	}

	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

// RemoveNodes implements api.Batch.
func (ba *rocksdbBatch) RemoveNodes(nodes []node.Node) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/rocksdb: cannot remove nodes in chunk mode")
	}

	for _, n := range nodes {
		ba.updatedNodes = append(ba.updatedNodes, updatedNode{
			Removed: true,
			Hash:    n.GetHash(),
		})
	}
	return nil
}

// Reset implements api.Batch.
func (ba *rocksdbBatch) Reset() {
	ba.bat.Destroy()
	if ba.multipartNodes != nil {
		ba.multipartNodes.Destroy()
	}
	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil
}

type rocksdbSubtree struct {
	batch *rocksdbBatch
}

func (s *rocksdbSubtree) PutNode(_ node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	cf := s.batch.db.getColumnFamilyForType(s.batch.rootType)
	h := ptr.Node.GetHash()
	s.batch.updatedNodes = append(s.batch.updatedNodes, updatedNode{Hash: h})
	nodeKey := nodeKeyFmt.Encode(&h)
	if s.batch.multipartNodes != nil {
		if err = withTimestampRead(s.batch.version, func(readOpts *grocksdb.ReadOptions) error {
			item, err := s.batch.db.db.GetCF(readOpts, cf, nodeKey)
			if err != nil {
				return err
			}
			defer item.Free()
			if !item.Exists() {
				th := node.TypedHashFromParts(s.batch.rootType, h)
				s.batch.multipartNodes.Put(multipartRestoreNodeLogKeyFmt.Encode(&th), []byte{})
			}
			return nil
		}); err != nil {
			return err
		}
	}

	ts := timestampFromVersion(s.batch.version)
	s.batch.bat.PutCFWithTS(cf, nodeKey, ts[:], data)
	return nil
}

func (s *rocksdbSubtree) VisitCleanNode(node.Depth, *node.Pointer) error {
	return nil
}

func (s *rocksdbSubtree) Commit() error {
	return nil
}
