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
	v, err := b.GetBatch(ctx, []api.Key{key})
	if err != nil {
		return nil, err
	}

	if v[0] == nil {
		return nil, api.ErrKeyNotFound
	}

	return v[0], nil
}

func (b *boltBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	var values [][]byte
	if err := b.db.View(func(tx *bolt.Tx) error {
		for _, key := range keys {
			// Ensure the key is not expired.
			bkt := tx.Bucket(bktExpirations)
			bkt = bkt.Bucket(bktByKey)
			rawExp := bkt.Get(key[:])
			if rawExp == nil {
				values = append(values, nil)
				continue
			}
			if exp := epochTimeFromRaw(rawExp); exp < epoch {
				values = append(values, nil)
				continue
			}

			// Retreive the value.
			bkt = tx.Bucket(bktValues)
			value := append([]byte{}, bkt.Get(key[:])...) // MUST copy.
			values = append(values, value)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return values, nil
}

func (b *boltBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	return b.InsertBatch(ctx, []api.Value{api.Value{Data: value, Expiration: expiration}})
}

func (b *boltBackend) InsertBatch(ctx context.Context, values []api.Value) error {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	b.logger.Debug("InsertBatch",
		"values", values,
	)

	// Hash all values first to avoid doing it inside the transaction which
	// holds a write lock.
	var hashes []api.Key
	for _, value := range values {
		hashes = append(hashes, api.HashStorageKey(value.Data))
	}

	err := b.db.Update(func(tx *bolt.Tx) error {
		modified := false

		for index, value := range values {
			bkt := tx.Bucket(bktExpirations)
			keys := bkt.Bucket(bktByKey)
			exps := bkt.Bucket(bktByExpiration)
			values := tx.Bucket(bktValues)

			key := hashes[index]
			expEpoch := epoch + epochtime.EpochTime(value.Expiration)

			var err error

			// Iff the key exists in the database already, remove
			// it's by-expiration index entry.
			if oldExp := keys.Get(key[:]); oldExp != nil {
				// The expiration time is identical.  Nothing to do, as
				// the value is identical by definition (or there is a hash
				// collision).
				if epochTimeFromRaw(oldExp) == expEpoch {
					continue
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

			if err = values.Put(key[:], value.Data); err != nil {
				return err
			}

			modified = true
		}

		if !modified {
			return errIdempotent
		}

		return nil
	})
	if err == errIdempotent {
		// Squelch internal error used to roll back the transaction for
		// the case where the value already is in the store.
		err = nil
	}

	return err
}

func (b *boltBackend) GetKeys() (<-chan api.KeyInfo, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	kiChan := make(chan api.KeyInfo)

	go func() {
		defer close(kiChan)
		if err := b.db.View(func(tx *bolt.Tx) error {
			bkt := tx.Bucket(bktExpirations)
			bkt = bkt.Bucket(bktByKey)
			return bkt.ForEach(func(k, v []byte) error {
				// Omit expired keys.
				exp := epochTimeFromRaw(v)
				if exp < epoch {
					return nil
				}

				ki := api.KeyInfo{
					Expiration: exp,
				}
				copy(ki.Key[:], k)
				kiChan <-ki

				return nil
			})
		}); err != nil {
			b.logger.Error("boltBackend GetKeys View", "err", err)
		}
	}()

	return kiChan, nil
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
