// Package bolt implements the BoltDB backed storage backend.
package bolt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"
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
	dbVersion   = []byte{0x01}

	bktValues = []byte("values")

	bktExpirations  = []byte("expirations")
	bktByKey        = []byte("byKey")
	bktByExpiration = []byte("byExpiration")

	errIdempotent = errors.New("storage/bolt: write has no effect")
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
		// Ensure the key is not expired.
		bkt := tx.Bucket(bktExpirations)
		bkt = bkt.Bucket(bktByKey)
		rawExp := bkt.Get(key[:])
		if rawExp == nil {
			return api.ErrKeyNotFound
		}
		if exp := epochTimeFromRaw(rawExp); exp < epoch {
			return api.ErrKeyExpired
		}

		// Retreive the value.
		bkt = tx.Bucket(bktValues)
		value = append([]byte{}, bkt.Get(key[:])...) // MUST copy.

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

	err := b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktExpirations)
		keys := bkt.Bucket(bktByKey)
		exps := bkt.Bucket(bktByExpiration)
		values := tx.Bucket(bktValues)

		var err error

		// Iff the key exists in the database already, remove
		// it's by-expiration index entry.
		if oldExp := keys.Get(key[:]); oldExp != nil {
			// The expiration time is identical.  Nothing to do, as
			// the value is identical by definition (or there is a hash
			// collision).
			if epochTimeFromRaw(oldExp) == expEpoch {
				return errIdempotent
			}

			if bkt = exps.Bucket(oldExp); bkt != nil {
				if err = bkt.Delete(key[:]); err != nil {
					return err
				}
			}
		}

		rawExp := epochTimeToRaw(expEpoch)
		bkt, err = exps.CreateBucketIfNotExists(rawExp)
		if err != nil {
			return err
		}
		if err = bkt.Put(key[:], rawExp); err != nil {
			return err
		}

		if err = keys.Put(key[:], rawExp); err != nil {
			return err
		}

		return values.Put(key[:], value)
	})
	if err == errIdempotent {
		// Squelch internal error used to roll back the transaction for
		// the case where the value already is in the store.
		err = nil
	}

	return err
}

func (b *boltBackend) GetKeys(ctx context.Context) ([]*api.KeyInfo, error) {
	var kiVec []*api.KeyInfo

	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	if err := b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktExpirations)
		bkt = bkt.Bucket(bktByKey)
		return bkt.ForEach(func(k, v []byte) error {
			// Omit expired keys.
			exp := epochTimeFromRaw(v)
			if exp < epoch {
				return nil
			}

			ki := &api.KeyInfo{
				Expiration: exp,
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
		bkt := tx.Bucket(bktExpirations)
		keys := bkt.Bucket(bktByKey)
		exps := bkt.Bucket(bktByExpiration)
		values := tx.Bucket(bktValues)

		cur := exps.Cursor()
		rawExp, _ := cur.First()
		for rawExp != nil {
			exp := epochTimeFromRaw(rawExp)
			if exp >= epoch {
				break
			}

			// Every single key in this bucket is expired.
			keyCur := exps.Bucket(rawExp).Cursor()
			for key, _ := keyCur.First(); key != nil; key, _ = keyCur.Next() {
				if err := keys.Delete(key); err != nil {
					return err
				}
				if err := values.Delete(key); err != nil {
					return err
				}
			}
			if err := exps.DeleteBucket(rawExp); err != nil {
				return err
			}

			rawExp, _ = cur.Next()
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

func (b *boltBackend) Initialized() <-chan struct{} {
	return b.sweeper.Initialized()
}

// New constructs a new BoltDB backed storage Backend instance, using
// the provided path for the database.
func New(fn string, timeSource epochtime.Backend) (api.Backend, error) {
	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bktValues); err != nil {
			return err
		}
		bkt, err := tx.CreateBucketIfNotExists(bktExpirations)
		if err != nil {
			return err
		}
		if _, err = bkt.CreateBucketIfNotExists(bktByKey); err != nil {
			return err
		}
		if _, err = bkt.CreateBucketIfNotExists(bktByExpiration); err != nil {
			return err
		}
		bkt, err = tx.CreateBucketIfNotExists(bktMetadata)
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

func epochTimeFromRaw(b []byte) epochtime.EpochTime {
	return epochtime.EpochTime(binary.LittleEndian.Uint64(b))
}

func epochTimeToRaw(t epochtime.EpochTime) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(t))

	return tmp[:]
}
