// Package bolt implements the BoltDB backed storage backend.
package bolt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	bolt "github.com/coreos/bbolt"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "bolt"

	// DBFile is the default backing store filename.
	DBFile = "storage.bolt.db"
)

var (
	_ api.Backend          = (*boltBackend)(nil)
	_ api.SweepableBackend = (*boltBackend)(nil)

	bktMetadata = []byte("metadata")
	keyVersion  = []byte("version")
	dbVersion   = []byte{0x00}

	bktStore      = []byte("store")
	keyValue      = []byte("value")
	keyExpiration = []byte("expiration")
)

type boltBackend struct {
	logger  *logging.Logger
	db      *bolt.DB
	sweeper *api.Sweeper

	closeOnce sync.Once
}

func (b *boltBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	var value []byte
	if err := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktStore)
		if bkt = bkt.Bucket(key[:]); bkt == nil {
			return api.ErrKeyNotFound
		}
		if boltGetExpiration(bkt) < epoch {
			return api.ErrKeyExpired
		}

		v := bkt.Get(keyValue)
		value = append([]byte{}, v...) // MUST copy.

		return nil
	}); err != nil {
		return nil, err
	}

	return value, nil
}

func (b *boltBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	key := api.HashStorageKey(value)
	expEpoch := epoch + epochtime.EpochTime(expiration)

	b.logger.Debug("Insert",
		"key", key,
		"value", hex.EncodeToString(value),
		"expiration", expEpoch,
	)

	return b.db.Update(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(bktStore)

		bkt, err := storeBkt.CreateBucketIfNotExists(key[:])
		if err != nil {
			return err
		}
		if err = boltSetExpiration(bkt, expEpoch); err != nil {
			return err
		}
		return bkt.Put(keyValue, value)
	})
}

func (b *boltBackend) GetKeys(ctx context.Context) ([]*api.KeyInfo, error) {
	var kiVec []*api.KeyInfo

	if err := b.db.View(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(bktStore)
		return storeBkt.ForEach(func(k, v []byte) error {
			bkt := storeBkt.Bucket(k)
			ki := &api.KeyInfo{
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

func (b *boltBackend) PurgeExpired(epoch epochtime.EpochTime) {
	if err := b.db.Update(func(tx *bolt.Tx) error {
		storeBkt := tx.Bucket(bktStore)

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

func (b *boltBackend) Cleanup() {
	b.closeOnce.Do(func() {
		b.sweeper.Close()
		_ = b.db.Close()
	})
}

// New constructs a new BoltDB backed storage Backend instance, using
// the provided path for the database.
func New(fn string, timeSource epochtime.Backend) (api.Backend, error) {
	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bktStore); err != nil {
			return err
		}
		bkt, err := tx.CreateBucketIfNotExists(bktMetadata)
		if err != nil {
			return err
		}

		ver := bkt.Get(keyVersion)
		if ver == nil {
			return bkt.Put(keyVersion, dbVersion)
		}

		if !bytes.Equal(ver, dbVersion) {
			return fmt.Errorf("storage/bolt: incompatible BoltDB store version: '%v'", hex.EncodeToString(ver))
		}

		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	b := &boltBackend{
		logger: logging.GetLogger("storage/bolt"),
		db:     db,
	}
	b.sweeper = api.NewSweeper(b, timeSource)

	return b, nil
}

func boltGetExpiration(bkt *bolt.Bucket) epochtime.EpochTime {
	v := bkt.Get(keyExpiration)
	if v == nil {
		panic("storage/bolt: no expiration time set for entry")
	}

	exp := binary.LittleEndian.Uint64(v)
	return epochtime.EpochTime(exp)
}

func boltSetExpiration(bkt *bolt.Bucket, expiration epochtime.EpochTime) error {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(expiration))

	return bkt.Put(keyExpiration, tmp[:])
}
