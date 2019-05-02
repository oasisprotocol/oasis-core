package indexer

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/runtime"
)

// ExactBackendName is the name of the exact backend.
const (
	ExactBackendName = "exact"

	exactIndexFile = "exact-tag-index.bolt.db"
)

var (
	_ Backend = (*exactBackend)(nil)
)

// The database layout for indices is as follows:
//
// * Bucket <runtime>
//   - Bucket block
//     - Bucket tag to location index
//       - <len(key)><key><len(value)><value><round> = ""
//   - Bucket transaction
//     - Bucket tag to location index
//       - <len(key)><key><len(value)><value><round><idx> = ""
//
// The keys are encoded to allow queries returning multiple results
// for the same key/value combination.
var (
	bktIndexBlock = []byte("\x00")
	bktIndexTxn   = []byte("\x01")

	bktIndexTagToLoc = []byte("\x00")
)

type exactBackend struct {
	logger *logging.Logger

	db *bolt.DB
}

// encodeKeyPrefix encodes the raw key to be stored into the underlying
// database.
func encodeKey(key, value []byte, round *uint64, txnIdx *int32) ([]byte, error) {
	keyLen := len(key)
	valueLen := len(value)
	if keyLen > maxKeyValueLength || valueLen > maxKeyValueLength {
		return nil, ErrTagTooLong
	}

	// The shortest variant is <len(key)><key><len(value)><value>.
	totalSize := 1 + keyLen + 1 + valueLen
	if round != nil {
		// With round <8-byte round> is appended.
		totalSize += 8
		if txnIdx != nil {
			// With transaction index <4-byte index> is appended.
			totalSize += 4
		}
	}

	enc := make([]byte, totalSize)
	offset := 0
	// Key length.
	enc[offset] = uint8(keyLen)
	offset++
	// Key.
	copy(enc[offset:offset+keyLen], key)
	offset += keyLen
	// Value length.
	enc[offset] = uint8(valueLen)
	offset++
	// Value.
	copy(enc[offset:offset+valueLen], value)
	offset += valueLen
	if round != nil {
		// Round.
		binary.BigEndian.PutUint64(enc[offset:offset+8], *round)
		offset += 8

		if txnIdx != nil {
			// Transaction index.
			binary.BigEndian.PutUint32(enc[offset:offset+4], uint32(*txnIdx))
		}
	}

	return enc, nil
}

func decodeKey(data []byte) (key []byte, value []byte, round uint64, txnIdx uint32) {
	offset := 0
	keyLen := int(data[offset])
	offset++
	key = data[offset : offset+keyLen]
	offset += keyLen
	valueLen := int(data[offset])
	offset++
	value = data[offset : offset+valueLen]
	offset += valueLen
	if len(data) >= offset+8 {
		round = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		if len(data) >= offset+4 {
			txnIdx = binary.BigEndian.Uint32(data[offset : offset+4])
		}
	}
	return
}

func (b *exactBackend) Index(runtimeID signature.PublicKey, round uint64, tags []runtime.Tag) error {
	return b.db.Batch(func(tx *bolt.Tx) error {
		// Create per-runtime bucket.
		bktRt, err := tx.CreateBucketIfNotExists(runtimeID[:])
		if err != nil {
			return err
		}

		for _, tag := range tags {
			// Block or transaction bucket.
			var bktType *bolt.Bucket
			var txnIdx *int32
			if tag.TxnIndex == runtime.TagTxnIndexBlock {
				bktType, err = bktRt.CreateBucketIfNotExists(bktIndexBlock)
				if err != nil {
					return err
				}
			} else {
				bktType, err = bktRt.CreateBucketIfNotExists(bktIndexTxn)
				if err != nil {
					return err
				}
				txnIdx = &tag.TxnIndex
			}

			// Tag to location bucket.
			var bktT2L *bolt.Bucket
			bktT2L, err = bktType.CreateBucketIfNotExists(bktIndexTagToLoc)
			if err != nil {
				return err
			}

			var key []byte
			key, err = encodeKey(tag.Key, tag.Value, &round, txnIdx)
			if err != nil {
				continue
			}

			if err = bktT2L.Put(key, []byte{}); err != nil {
				return err
			}

			// TODO: Update reverse index for pruning.
		}

		return nil
	})
}

func (b *exactBackend) queryBucket(runtimeID signature.PublicKey, bktName, key, value []byte) (uint64, uint32, error) {
	var round uint64
	var txnIdx uint32

	if txErr := b.db.View(func(tx *bolt.Tx) error {
		bktRt := tx.Bucket(runtimeID[:])
		if bktRt == nil {
			return ErrNotFound
		}

		bktType := bktRt.Bucket(bktName)
		if bktType == nil {
			return ErrNotFound
		}

		bktT2L := bktType.Bucket(bktIndexTagToLoc)
		if bktT2L == nil {
			return ErrNotFound
		}

		encKey, err := encodeKey(key, value, nil, nil)
		if err != nil {
			return err
		}

		c := bktT2L.Cursor()
		k, _ := c.Seek(encKey)
		if k == nil {
			return ErrNotFound
		}

		// Check if the retrieved key is the requested one.
		dKey, dValue, dRound, dTxnIdx := decodeKey(k)
		if !bytes.Equal(dKey, key) || !bytes.Equal(dValue, value) {
			return ErrNotFound
		}

		round = dRound
		txnIdx = dTxnIdx

		return nil
	}); txErr != nil {
		return 0, 0, txErr
	}

	return round, txnIdx, nil
}

func (b *exactBackend) QueryBlock(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, error) {
	round, _, err := b.queryBucket(runtimeID, bktIndexBlock, key, value)
	return round, err
}

func (b *exactBackend) QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, uint32, error) {
	return b.queryBucket(runtimeID, bktIndexTxn, key, value)
}

func (b *exactBackend) QueryTxns(ctx context.Context, runtimeID signature.PublicKey, query Query) (Results, error) {
	return nil, ErrUnsupported
}

func (b *exactBackend) Prune(runtimeID signature.PublicKey, round uint64) error {
	// TODO: Support pruning for the exact backend.
	return nil
}

func (b *exactBackend) Stop() {
	if err := b.db.Close(); err != nil {
		b.logger.Error("failed to close index",
			"err", err,
		)
	}
	b.db = nil
}

// NewExactBackend creates a new exact indexer backend.
func NewExactBackend(dataDir string) (Backend, error) {
	b := &exactBackend{
		logger: logging.GetLogger("client/indexer/exactBackend"),
	}

	var err error
	if b.db, err = bolt.Open(filepath.Join(dataDir, exactIndexFile), 0600, nil); err != nil {
		return nil, err
	}

	b.logger.Info("initialized tag indexer backend")

	// TODO: The file format could be versioned.

	return b, nil
}
