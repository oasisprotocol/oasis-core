package host

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"

	cmnBadger "github.com/oasislabs/oasis-core/go/common/badger"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
)

var (
	errInvalidKey = errors.New("invalid local storage key")

	runtimeKeyFmt = keyformat.New(0x00, &signature.PublicKey{}, []byte{})
)

type LocalStorage struct {
	logger *logging.Logger

	db *badger.DB
	gc *cmnBadger.GCWorker
}

func (s *LocalStorage) Get(id signature.PublicKey, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errInvalidKey
	}

	var value []byte
	if err := s.db.View(func(tx *badger.Txn) error {
		item, txErr := tx.Get(runtimeKeyFmt.Encode(&id, key))
		switch txErr {
		case nil:
		case badger.ErrKeyNotFound:
			return nil
		default:
			return txErr
		}

		return item.Value(func(val []byte) error {
			value = append([]byte{}, val...)
			return nil
		})
	}); err != nil {
		s.logger.Error("failed get",
			"err", err,
			"id", id,
			"key", hex.EncodeToString(key),
		)
		return nil, err
	}

	return cbor.FixSliceForSerde(value), nil
}

func (s *LocalStorage) Set(id signature.PublicKey, key, value []byte) error {
	if len(key) == 0 {
		return errInvalidKey
	}

	if err := s.db.Update(func(tx *badger.Txn) error {
		return tx.Set(runtimeKeyFmt.Encode(&id, key), value)
	}); err != nil {
		s.logger.Error("failed put",
			"err", err,
			"id", id,
			"key", hex.EncodeToString(key),
			"value", hex.EncodeToString(value),
		)
		return err
	}

	return nil
}

func (s *LocalStorage) Stop() {
	s.gc.Close()
	if err := s.db.Close(); err != nil {
		s.logger.Error("failed to close local storage",
			"err", err,
		)
	}
	s.db = nil
}

func NewLocalStorage(dataDir, fn string) (*LocalStorage, error) {
	s := &LocalStorage{
		logger: logging.GetLogger("worker/common/host/localStorage"),
	}

	opts := badger.DefaultOptions(filepath.Join(dataDir, fn))
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(s.logger))
	opts = opts.WithSyncWrites(true)
	opts = opts.WithCompression(options.None)
	// Reduce cache size to 128 KiB as the default is 1 GiB.
	opts = opts.WithMaxCacheSize(128 * 1024)

	var err error
	if s.db, err = badger.Open(opts); err != nil {
		return nil, fmt.Errorf("failed to open local storage database: %w", err)
	}
	s.gc = cmnBadger.NewGCWorker(s.logger, s.db)

	// TODO: The file format could be versioned, but it's not like this
	// really is subject to change.

	return s, nil
}
