// Package persistent provides a wrapper around a key-value database for use as
// general node-wide storage.
package persistent

import (
	"errors"
	"path/filepath"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
)

const dbName = "persistent-store.db"

var (
	// ErrNotFound is returned when the requested key could not be found in the database.
	ErrNotFound = errors.New("persistent: key not found in database")
)

type StoreTxFunc func(*bolt.Tx, *bolt.Bucket) error

// CommonStore is the interface to the common storage for the node.
type CommonStore struct {
	db *bolt.DB
}

// Close closes the database handle.
func (cs *CommonStore) Close() {
	cs.db.Close()
}

// GetServiceStore returns a handle to a per-service bucket for the given service.
func (cs *CommonStore) GetServiceStore(name string) (*ServiceStore, error) {
	byteName := []byte(name)
	err := cs.db.Update(func(tx *bolt.Tx) error {
		_, berr := tx.CreateBucketIfNotExists(byteName)
		return berr
	})
	if err != nil {
		return nil, err
	}

	ss := &ServiceStore{
		store:    cs,
		name:     name,
		byteName: byteName,
	}
	return ss, nil
}

// NewCommonStore opens the default common node storage and returns a handle.
func NewCommonStore(dataDir string) (*CommonStore, error) {
	db, err := bolt.Open(filepath.Join(dataDir, dbName), 0600, nil)
	if err != nil {
		return nil, err
	}

	cs := &CommonStore{
		db: db,
	}

	return cs, nil
}

// ServiceStore is a storage wrapper that automatically calls view callbacks with appropriate buckets.
type ServiceStore struct {
	store *CommonStore

	name     string
	byteName []byte
}

// Close invalidates the per-service database handle.
func (ss *ServiceStore) Close() {
	ss.store = nil
}

// View executes the given callback within a read-only transaction.
func (ss *ServiceStore) View(cb StoreTxFunc) error {
	return ss.store.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(ss.byteName)
		return cb(tx, bkt)
	})
}

// Update executes the given callback within a read-write transaction.
func (ss *ServiceStore) Update(cb StoreTxFunc) error {
	return ss.store.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(ss.byteName)
		return cb(tx, bkt)
	})
}

// GetCBOR is a helper for retrieving CBOR-serialized values.
func (ss *ServiceStore) GetCBOR(key []byte, value interface{}) error {
	return ss.View(func(tx *bolt.Tx, bkt *bolt.Bucket) error {
		bytes := bkt.Get(key)
		if bytes != nil {
			return cbor.Unmarshal(bytes, value)
		}
		return ErrNotFound
	})
}

// PutCBOR is a helper for storing CBOR-serialized values.
func (ss *ServiceStore) PutCBOR(key []byte, value interface{}) error {
	return ss.Update(func(tx *bolt.Tx, bkt *bolt.Bucket) error {
		bytes := cbor.Marshal(value)
		return bkt.Put(key, bytes)
	})
}
