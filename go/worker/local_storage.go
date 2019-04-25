package worker

import (
	"encoding/hex"
	"errors"
	"path/filepath"

	bolt "go.etcd.io/bbolt"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
)

var errInvalidKey = errors.New("invalid local storage key")

type localStorage struct {
	logger *logging.Logger

	db *bolt.DB
}

func (s *localStorage) Get(id signature.PublicKey, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errInvalidKey
	}

	var value []byte
	if txErr := s.db.View(func(tx *bolt.Tx) error {
		// If the runtime ID has never stored anything, the bucket will not exist.
		// Treat this as the same as the key not being present.
		bkt := tx.Bucket(id[:])
		if bkt == nil {
			return nil
		}

		value = bkt.Get(key)

		return nil
	}); txErr != nil {
		s.logger.Error("failed get",
			"err", txErr,
			"id", id,
			"key", hex.EncodeToString(key),
		)
		return nil, txErr
	}

	return cbor.FixSliceForSerde(value), nil
}

func (s *localStorage) Set(id signature.PublicKey, key, value []byte) error {
	if len(key) == 0 {
		return errInvalidKey
	}

	txErr := s.db.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucketIfNotExists(id[:])
		if err != nil {
			return err
		}

		if len(value) == 0 {
			err = bkt.Delete(key)
		} else {
			err = bkt.Put(key, value)
		}

		return err
	})
	if txErr != nil {
		s.logger.Error("failed put",
			"err", txErr,
			"id", id,
			"key", hex.EncodeToString(key),
			"value", hex.EncodeToString(value),
		)
	}

	return txErr
}

func (s *localStorage) Stop() {
	if err := s.db.Close(); err != nil {
		s.logger.Error("failed to close local storage",
			"err", err,
		)
	}
	s.db = nil
}

func newLocalStorage(dataDir string) (*localStorage, error) {
	s := &localStorage{
		logger: logging.GetLogger("worker/localStorage"),
	}

	var err error
	if s.db, err = bolt.Open(filepath.Join(dataDir, "worker-local-storage.bolt.db"), 0600, nil); err != nil {
		return nil, err
	}

	// TODO: The file format could be versioned, but it's not like this
	// really is subject to change.

	return s, nil
}
