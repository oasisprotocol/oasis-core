package pebbledb

import (
	"errors"
	"fmt"
	"io"

	"github.com/cockroachdb/pebble"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

type pebbledbBatch struct {
	api.BaseBatch

	db             *pebbleNodeDB
	bat            *pebble.Batch
	multipartNodes *pebble.Batch

	oldRoot node.Root
	chunk   bool

	version  uint64
	rootType node.RootType

	writeLog     writelog.WriteLog
	annotations  writelog.Annotations
	updatedNodes []updatedNode
}

// Commit implements api.Batch.
func (ba *pebbledbBatch) Commit(root node.Root) error { // nolint: gocyclo
	defer ba.bat.Close()
	if ba.multipartNodes != nil {
		defer ba.multipartNodes.Close()
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

	rootsMeta, err := loadRootsMetadata(ba.db.db, root.Version)
	if err != nil {
		return err
	}

	rootHash := node.TypedHashFromRoot(root)

	if err = putVersioned(ba.bat, rootNodeMVCCKeyFmt.Encode(&rootHash), root.Version, []byte{}); err != nil {
		return err
	}
	if ba.multipartNodes != nil {
		if err = ba.multipartNodes.Set(multipartRestoreRootLogKeyFmt.Encode(&rootHash), []byte{}, nil); err != nil {
			return err
		}
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
		if err = rootsMeta.save(ba.bat); err != nil {
			return err
		}
	}

	if ba.chunk {
		// Skip most of metadata updates if we are just importing chunks.
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &rootHash)
		if err = ba.bat.Set(key, cbor.Marshal([]updatedNode{}), nil); err != nil {
			return err
		}
	} else {
		// Update the root link for the old root.
		oldRootHash := node.TypedHashFromRoot(ba.oldRoot)
		if !ba.oldRoot.Hash.IsEmpty() {
			if (ba.oldRoot.Version+1) < ba.db.meta.getEarliestVersion() && ba.oldRoot.Version != root.Version {
				return api.ErrPreviousVersionMismatch
			}

			var oldRootsMeta *rootsMetadata
			oldRootsMeta, err = loadRootsMetadata(ba.db.db, ba.oldRoot.Version)
			if err != nil {
				return err
			}

			// Check if oldRootsMeta was updated in this batch.
			var key []byte
			var closer io.Closer
			key, closer, err = ba.bat.Get(rootsMetadataKeyFmt.Encode(ba.oldRoot.Version))
			switch {
			case err == nil:
				defer closer.Close()
				if err = cbor.Unmarshal(key, &oldRootsMeta); err != nil {
					panic(err)
				}
				if _, ok := oldRootsMeta.Roots[oldRootHash]; !ok {
					return api.ErrRootNotFound
				}

				oldRootsMeta.Roots[oldRootHash] = append(oldRootsMeta.Roots[oldRootHash], rootHash)
				if err = oldRootsMeta.save(ba.bat); err != nil {
					return err
				}
			case errors.Is(err, pebble.ErrNotFound):
				// Not found.
				return api.ErrRootNotFound // TODO: ?OK?
			default:
				// Error.
				panic(err)
			}
		}

		// Store updated nodes (only needed until the version is finalized).
		key := rootUpdatedNodesKeyFmt.Encode(root.Version, &rootHash)
		if err = ba.bat.Set(key, cbor.Marshal(ba.updatedNodes), nil); err != nil {
			return err
		}

		// Store write log.
		if ba.writeLog != nil && ba.annotations != nil {
			log := api.MakeHashedDBWriteLog(ba.writeLog, ba.annotations)
			bytes := cbor.Marshal(log)
			key := writeLogMVCCKeyFmt.Encode(root.Version, &rootHash, &oldRootHash)
			if err = putVersioned(ba.bat, key, root.Version, bytes); err != nil {
				return err
			}
		}
	}

	// Flush node updates.
	if ba.multipartNodes != nil {
		if err = ba.db.db.Apply(ba.multipartNodes, ba.db.writeOptions); err != nil {
			return fmt.Errorf("mkvs/pebbledb: failed to flush node log batch: %w", err)
		}
	}
	if err = ba.db.db.Apply(ba.bat, ba.db.writeOptions); err != nil {
		return fmt.Errorf("mkvs/pebbledb: failed to flush batch: %w", err)
	}

	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil

	return ba.BaseBatch.Commit(root)
}

// MaybeStartSubtree implements api.Batch.
func (ba *pebbledbBatch) MaybeStartSubtree(subtree api.Subtree, _ node.Depth, _ *node.Pointer) api.Subtree {
	if subtree == nil {
		return &pebbledbSubtree{batch: ba}
	}
	return subtree
}

// PutWriteLog implements api.Batch.
func (ba *pebbledbBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/pebbledb: cannot put write log in chunk mode")
	}
	if ba.db.discardWriteLogs {
		return nil
	}

	ba.writeLog = writeLog
	ba.annotations = annotations
	return nil
}

// RemoveNodes implements api.Batch.
func (ba *pebbledbBatch) RemoveNodes(nodes []node.Node) error {
	if ba.chunk {
		return fmt.Errorf("mkvs/pebbledb: cannot remove nodes in chunk mode")
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
func (ba *pebbledbBatch) Reset() {
	ba.bat.Close()
	if ba.multipartNodes != nil {
		ba.multipartNodes.Close()
	}
	ba.writeLog = nil
	ba.annotations = nil
	ba.updatedNodes = nil
}

type pebbledbSubtree struct {
	batch *pebbledbBatch
}

func (s *pebbledbSubtree) PutNode(_ node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	h := ptr.Node.GetHash()
	s.batch.updatedNodes = append(s.batch.updatedNodes, updatedNode{Hash: h})
	nodeKey := nodeMVCCKeyFmt.Encode(&h)
	if s.batch.multipartNodes != nil {
		err = existsVersioned(s.batch.db.db, nodeKey, s.batch.version)
		switch {
		case err == nil:
		case errors.Is(err, errNotFound):
			// Node does not exist, add to multipartNodes.
			th := node.TypedHashFromParts(s.batch.rootType, h)
			if err = s.batch.multipartNodes.Set(multipartRestoreNodeLogKeyFmt.Encode(&th), []byte{}, nil); err != nil {
				return err
			}
		default:
			return err
		}
	}

	return putVersioned(s.batch.bat, nodeKey, s.batch.version, data)
}

func (s *pebbledbSubtree) VisitCleanNode(node.Depth, *node.Pointer) error {
	return nil
}

func (s *pebbledbSubtree) Commit() error {
	return nil
}
