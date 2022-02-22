// Package localstorage implements untrusted local storage that is used
// by runtimes to store per-node key/value pairs.
package localstorage

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dgraph-io/badger/v3"
	"github.com/dgraph-io/badger/v3/options"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

var (
	errInvalidKey = errors.New("invalid local storage key")

	_ LocalStorage = (*localStorage)(nil)
)

// LocalStorage is the untrusted local storage interface.
type LocalStorage interface {
	// Get retrieves a previously stored value under the given key.
	Get(key []byte) ([]byte, error)

	// Set sets a key to a specific value.
	Set(key, value []byte) error

	// Stop stops local storage.
	Stop()
}

type localStorage struct {
	logger *logging.Logger

	db *badger.DB
	gc *cmnBadger.GCWorker
}

func (s *localStorage) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errInvalidKey
	}

	var value []byte
	if err := s.db.View(func(tx *badger.Txn) error {
		item, txErr := tx.Get(key)
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
			"key", hex.EncodeToString(key),
		)
		return nil, err
	}

	return cbor.FixSliceForSerde(value), nil
}

func (s *localStorage) Set(key, value []byte) error {
	if len(key) == 0 {
		return errInvalidKey
	}

	if err := s.db.Update(func(tx *badger.Txn) error {
		return tx.Set(key, value)
	}); err != nil {
		s.logger.Error("failed put",
			"err", err,
			"key", hex.EncodeToString(key),
			"value", hex.EncodeToString(value),
		)
		return err
	}

	return nil
}

func (s *localStorage) Stop() {
	s.gc.Close()
	if err := s.db.Close(); err != nil {
		s.logger.Error("failed to close local storage",
			"err", err,
		)
	}
	s.db = nil
}

// New creates new untrusted local storage.
func New(dataDir, fn string, runtimeID common.Namespace) (LocalStorage, error) {
	s := &localStorage{
		logger: logging.GetLogger("runtime/localstorage").With("runtime_id", runtimeID),
	}

	opts := badger.DefaultOptions(filepath.Join(dataDir, fn))
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(s.logger))
	opts = opts.WithSyncWrites(true)
	opts = opts.WithCompression(options.None)

	var err error
	if s.db, err = badger.Open(opts); err != nil {
		return nil, fmt.Errorf("failed to open local storage database: %w", err)
	}
	s.gc = cmnBadger.NewGCWorker(s.logger, s.db)

	// TODO: The file format could be versioned, but it's not like this
	// really is subject to change.

	return s, nil
}
