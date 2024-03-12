package pathbadger

import (
	"bytes"
	"context"
	"fmt"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// internalWriteLog is an internal database representation of a write log. The first byte denotes
// whether a given key has been inserted or removed. In case the key has been removed, the rest of
// the entry contains the removed key. In case the key has been inserted, the rest of the entry
// contains the index and version of the corresponding leaf node.
type internalWriteLog [][]byte

const (
	internalWriteLogKindInsert = 0x01
	internalWriteLogKindDelete = 0x02
)

// makeInternalWriteLog converts the given write log into an internal database representation.
func makeInternalWriteLog(writeLog writelog.WriteLog, annotations writelog.Annotations) internalWriteLog {
	log := make(internalWriteLog, 0, len(writeLog))
	for i, entry := range writeLog {
		if annotations[i].InsertedNode == nil {
			log = append(log, append([]byte{internalWriteLogKindDelete}, entry.Key...))
		} else {
			iptr := annotations[i].InsertedNode.DBInternal.(*dbPtr)
			log = append(log, append([]byte{internalWriteLogKindInsert}, iptr.dbKey()...))
		}
	}
	return log
}

// storeInternalWriteLog stores the given write log using an internal database representation.
func storeInternalWriteLog(
	batch *badger.WriteBatch,
	startRootHash api.TypedHash,
	endRootHash api.TypedHash,
	endRootVersion uint64,
	writeLog writelog.WriteLog,
	annotations writelog.Annotations,
) error {
	if writeLog == nil || annotations == nil {
		return nil
	}
	intLog := makeInternalWriteLog(writeLog, annotations)

	key := writeLogKeyFmt.Encode(endRootVersion, &endRootHash, &startRootHash)
	if err := batch.Set(key, cbor.Marshal(intLog)); err != nil {
		return fmt.Errorf("mkvs/pathbadger: set new write log returned error: %w", err)
	}
	return nil
}

// Implements api.NodeDB.
func (d *badgerNodeDB) GetWriteLog(_ context.Context, startRoot, endRoot node.Root) (writelog.Iterator, error) {
	if d.discardWriteLogs {
		return nil, api.ErrWriteLogNotFound
	}
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}
	if err := d.sanityCheckNamespace(&startRoot.Namespace); err != nil {
		return nil, err
	}
	// If the version is earlier than the earliest version, we don't have the roots.
	if endRoot.Version < d.meta.getEarliestVersion() {
		return nil, api.ErrWriteLogNotFound
	}
	// If difference between versions is more than 1 we can reject early.
	if endRoot.Version-startRoot.Version > 1 {
		return nil, api.ErrWriteLogNotFound
	}

	tx := d.db.NewTransactionAt(versionToTs(endRoot.Version), false)
	defer tx.Discard()

	// Check if the root actually exists.
	if err := d.checkRootExists(tx, endRoot); err != nil {
		return nil, err
	}

	startRootHash := api.TypedHashFromRoot(startRoot)
	endRootHash := api.TypedHashFromRoot(endRoot)

	item, err := tx.Get(writeLogKeyFmt.Encode(endRoot.Version, &endRootHash, &startRootHash))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		return nil, api.ErrWriteLogNotFound
	default:
		return nil, fmt.Errorf("mkvs/pathbadger: failed to fetch write log: %w", err)
	}

	var log internalWriteLog
	if err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &log)
	}); err != nil {
		return nil, fmt.Errorf("mkvs/pathbadger: failed to unmarshal write log: %w", err)
	}

	// Determine sequence number for the root. All finalized roots use a seqNo of zero.
	seqNo, _ := d.meta.getPendingRootSeqNo(endRoot.Version, endRootHash)
	if seqNo != 0 {
		return nil, api.ErrWriteLogNotFound
	}

	// Note the root node dbKey as an entry could also end there.
	rootNodeDbKey := encodeNodeKey(endRoot.Version, 0)

	// Resolve the write log.
	wl := make(writelog.WriteLog, 0, len(log))
	for _, key := range log {
		switch key[0] {
		case internalWriteLogKindDelete:
			// Deletion.
			wl = append(wl, writelog.LogEntry{Key: key[1:]})
		case internalWriteLogKindInsert:
			// Insertion.
			if bytes.Equal(key[1:], rootNodeDbKey) {
				// Fetch the root node as a key ends there.
				var rootNodeKey, rootNodeValue []byte
				item, err = tx.Get(rootNodeKeyFmt.Encode(endRoot.Version, &endRootHash))
				if err != nil {
					return nil, fmt.Errorf("mkvs/pathbadger: failed to fetch root node: %w", err)
				}
				if err = item.Value(func(rawValue []byte) error {
					rootNodeKey, rootNodeValue, err = leafFromDb(rawValue)
					return err
				}); err != nil {
					return nil, fmt.Errorf("mkvs/pathbadger: failed to unmarshal root node: %w", err)
				}

				wl = append(wl, writelog.LogEntry{Key: rootNodeKey, Value: rootNodeValue})
				continue
			}

			item, err = tx.Get(finalizedNodeKeyFmt.Encode(byte(endRoot.Type), key[1:]))
			switch err {
			case nil:
				// Key has been inserted, resolve value from node.
				var key, value []byte
				if err = item.Value(func(rawValue []byte) error {
					key, value, err = leafFromDb(rawValue)
					return err
				}); err != nil {
					return nil, fmt.Errorf("mkvs/pathbadger: failed to unmarshal node: %w", err)
				}
				wl = append(wl, writelog.LogEntry{Key: key, Value: value})
			default:
				return nil, fmt.Errorf("mkvs/pathbadger: failed to fetch node: %w", err)
			}
		default:
			return nil, fmt.Errorf("mkvs/pathbadger: internal write log is corrupted")
		}
	}

	return writelog.NewStaticIterator(wl), nil
}
