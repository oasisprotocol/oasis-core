package api

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

// HashedDBWriteLog is a write log helper for database backends that can reference nodes by hash.
type HashedDBWriteLog []HashedDBLogEntry

// HashedDBLogEntry is a single write log entry for HashedDBWriteLog.
type HashedDBLogEntry struct {
	Key          []byte
	InsertedHash *hash.Hash
}

// MakeHashedDBWriteLog converts the given write log and annotations into a serializable slice with hash node references.
func MakeHashedDBWriteLog(writeLog writelog.WriteLog, annotations writelog.WriteLogAnnotations) HashedDBWriteLog {
	log := make(HashedDBWriteLog, len(writeLog))
	for idx, entry := range writeLog {
		var h *hash.Hash
		if annotations[idx].InsertedNode != nil {
			h = &annotations[idx].InsertedNode.Node.(*node.LeafNode).Hash
		}
		log[idx] = HashedDBLogEntry{
			Key:          entry.Key,
			InsertedHash: h,
		}
	}
	return log
}

// ReviveHashedDBWriteLog is a helper for hashed database backends that converts a HashedDBWriteLog into a WriteLog.
func ReviveHashedDBWriteLog(ctx context.Context, hlog HashedDBWriteLog, getter func(hash.Hash) (*node.LeafNode, error)) (WriteLogIterator, error) {
	pipe := NewPipeWriteLogIterator(ctx)
	go func() {
		defer pipe.Close()
		for _, entry := range hlog {
			var newEntry *writelog.LogEntry
			if entry.InsertedHash == nil {
				newEntry = &writelog.LogEntry{
					Key:   entry.Key,
					Value: nil,
				}
			} else {
				node, err := getter(*entry.InsertedHash)
				if err != nil {
					_ = pipe.PutError(err)
					break
				}
				newEntry = &writelog.LogEntry{
					Key:   entry.Key,
					Value: node.Value.Value,
				}
			}
			if err := pipe.Put(newEntry); err != nil {
				_ = pipe.PutError(err)
				break
			}
		}
	}()
	return &pipe, nil
}
