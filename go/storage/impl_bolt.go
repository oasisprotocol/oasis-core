package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/epochtime"

	bolt "github.com/coreos/bbolt"
)

const boltDBFile = "storage.bolt.db"

var (
	_ Backend          = (*BoltBackend)(nil)
	_ backendSweepable = (*BoltBackend)(nil)

	boltBktMetadata = []byte("metadata")
	boltKeyVersion  = []byte("version")
	boltVersion     = []byte{0x00}

	boltBktStore      = []byte("store")
	boltKeyValue      = []byte("value")
	boltKeyExpiration = []byte("expiration")
)

// BoltBackend is a boltdb backed storage backend.
type BoltBackend struct {
	logger     *logging.Logger
	timeSource epochtime.TimeSource
	db         *bolt.DB
	sweeper    *backendSweeper

	closeOnce sync.Once
}

// Get returns the value for a specific immutable key.
func (b *BoltBackend) Get(key Key) ([]byte, error) {
	epoch, _ := b.timeSource.GetEpoch()

	var value []byte
	if err := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(boltBktStore)
		if bkt = bkt.Bucket(key[:]); bkt == nil {
			return ErrKeyNotFound
		}
		if boltGetExpiration(bkt) < epoch {
			return ErrKeyExpired
		}

		v := bkt.Get(boltKeyValue)
		value = append([]byte{}, v...) // MUST copy.

		return nil
	}); err != nil {
		return nil, err
	}

	return value, nil
}

// Insert inserts a specific value, which can later be retreived by
// it's hash.  The expiration is the number of epochs for which the
// value should remain available.
func (b *BoltBackend) Insert(value []byte, expiration uint64) error {
	key := HashStorageKey(value)
	epoch, _ := b.timeSource.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return ErrIncoherentTime
	}
	expEpoch := epoch + epochtime.EpochTime(expiration)

	b.logger.Debug("Insert",
		"key", key,
		"value", hex.EncodeToString(value),
		"expiration", expEpoch,
	)

	return b.db.Update(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(boltBktStore)

		bkt, err := storeBkt.CreateBucketIfNotExists(key[:])
		if err != nil {
			return err
		}
		if err = boltSetExpiration(bkt, expEpoch); err != nil {
			return err
		}
		return bkt.Put(boltKeyValue, value)
	})
}

// GetKeys returns all of the keys in the storage database, along
// with their associated metadata.
func (b *BoltBackend) GetKeys() ([]*KeyInfo, error) {
	var kiVec []*KeyInfo

	if err := b.db.View(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(boltBktStore)
		return storeBkt.ForEach(func(k, v []byte) error {
			bkt := storeBkt.Bucket(k)
			ki := &KeyInfo{
				Expiration: boltGetExpiration(bkt),
			}
			copy(ki.Key[:], k)
			kiVec = append(kiVec, ki)

			return nil
		})
	}); err != nil {
		return nil, err
	}

	return kiVec, nil
}

// PurgeExpired purges keys that expire before the provided epoch.
func (b *BoltBackend) PurgeExpired(epoch epochtime.EpochTime) {
	if err := b.db.Update(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(boltBktStore)

		cur := storeBkt.Cursor()
		for key, _ := cur.First(); key != nil; key, _ = cur.Next() {
			bkt := storeBkt.Bucket(key)
			if boltGetExpiration(bkt) < epoch {
				b.logger.Debug("Expire",
					"key", key,
				)
				if err := storeBkt.DeleteBucket(key); err != nil {
					return err
				}
			}
		}

		return nil
	}); err != nil {
		panic(err)
	}
}

// Cleanup closes/cleans up the storage backend.
func (b *BoltBackend) Cleanup() {
	b.closeOnce.Do(func() {
		b.sweeper.Close()
		_ = b.db.Close()
	})
}

// NewBoltBackend constructs a new BoltBackend instance, using the provided
// path for the database.
func NewBoltBackend(fn string, timeSource epochtime.TimeSource) (Backend, error) {
	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(boltBktStore); err != nil {
			return err
		}
		bkt, err := tx.CreateBucketIfNotExists(boltBktMetadata)
		if err != nil {
			return err
		}

		ver := bkt.Get(boltKeyVersion)
		if ver == nil {
			return bkt.Put(boltKeyVersion, boltVersion)
		}

		if !bytes.Equal(ver, boltVersion) {
			return fmt.Errorf("storage: incompatible boltdb store version: '%v'", hex.EncodeToString(ver))
		}

		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	b := &BoltBackend{
		logger:     logging.GetLogger("BoltStorageBackend"),
		timeSource: timeSource,
		db:         db,
	}
	b.sweeper = newBackendSweeper(b, timeSource)

	return b, nil
}

func boltGetExpiration(bkt *bolt.Bucket) epochtime.EpochTime {
	v := bkt.Get(boltKeyExpiration)
	if v == nil {
		panic("storage: no expiration time set for entry")
	}

	exp := binary.LittleEndian.Uint64(v)
	return epochtime.EpochTime(exp)
}

func boltSetExpiration(bkt *bolt.Bucket, expiration epochtime.EpochTime) error {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(expiration))

	return bkt.Put(boltKeyExpiration, tmp[:])
}
