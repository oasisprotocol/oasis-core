package history

import (
	"fmt"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBadger "github.com/oasisprotocol/oasis-core/go/common/badger"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const dbVersion = 1

var (
	// keyFormat is the namespace for the runtime history database key formats.
	keyFormat = keyformat.NewNamespace("runtime history db")

	// metadataKeyFmt is the metadata key format.
	//
	// Value is CBOR-serialized dbMetadata.
	metadataKeyFmt = keyFormat.New(0x01)
	// blockKeyFmt is the block index key format.
	//
	// Value is CBOR-serialized roothash.AnnotatedBlock.
	blockKeyFmt = keyFormat.New(0x02, uint64(0))

	// deprecatedRoundResultsKeyFmt is the deprecated round result index key format.
	//
	// Value is CBOR-serialized roothash.RoundResults.
	//
	// Deprecated: This key format is deprecated and will be removed in future versions
	// after we clean up the remaining round results from the block history (#6098).
	deprecatedRoundResultsKeyFmt = keyFormat.New(0x03, uint64(0)) //nolint:unused
)

type dbMetadata struct {
	// RuntimeID is the runtime ID this database is for.
	RuntimeID common.Namespace `json:"runtime_id"`
	// Version is the database schema version.
	Version uint64 `json:"version"`

	// LastConsensusHeight is the last consensus height.
	LastConsensusHeight int64 `json:"last_consensus_height"`
	// LastRound is the last round.
	LastRound uint64 `json:"last_round"`
}

// DB is the history database.
type DB struct {
	logger *logging.Logger

	db *badger.DB
	gc *cmnBadger.GCWorker
}

func newDB(fn string, runtimeID common.Namespace) (*DB, error) {
	logger := logging.GetLogger("runtime/history").With("path", fn)

	opts := badger.DefaultOptions(fn)
	opts = opts.WithLogger(cmnBadger.NewLogAdapter(logger))
	opts = opts.WithSyncWrites(true)
	opts = opts.WithCompression(options.None)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("runtime/history: failed to open database: %w", err)
	}

	gc := cmnBadger.NewGCWorker(logger, db)
	gc.Start()

	d := &DB{
		logger: logger,
		db:     db,
		gc:     gc,
	}

	// Ensure metadata is valid.
	if err = d.ensureMetadata(runtimeID); err != nil {
		d.close()
		return nil, err
	}

	return d, nil
}

func (d *DB) queryGetMetadata(tx *badger.Txn) (*dbMetadata, error) {
	item, err := tx.Get(metadataKeyFmt.Encode())
	if err != nil {
		return nil, err
	}

	var meta dbMetadata
	err = item.Value(func(val []byte) error {
		return cbor.Unmarshal(val, &meta)
	})
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func (d *DB) ensureMetadata(runtimeID common.Namespace) error {
	return d.db.Update(func(tx *badger.Txn) error {
		meta, err := d.queryGetMetadata(tx)
		switch err {
		case nil:
		case badger.ErrKeyNotFound:
			// Create new metadata section.
			meta := dbMetadata{
				RuntimeID: runtimeID,
				Version:   dbVersion,
			}
			return tx.Set(metadataKeyFmt.Encode(), cbor.Marshal(meta))
		default:
			return err
		}

		// Verify metadata section.
		if meta.Version != dbVersion {
			return fmt.Errorf("runtime/history: unsupported database version (expected: %d got: %d)",
				dbVersion,
				meta.Version,
			)
		}

		if !meta.RuntimeID.Equal(&runtimeID) {
			return fmt.Errorf("runtime/history: database for different runtime (expected: %s got: %s)",
				runtimeID,
				meta.RuntimeID,
			)
		}
		return nil
	})
}

func (d *DB) metadata() (*dbMetadata, error) {
	var meta *dbMetadata
	err := d.db.View(func(tx *badger.Txn) error {
		var err error
		meta, err = d.queryGetMetadata(tx)
		return err
	})
	if err != nil {
		return nil, err
	}

	return meta, nil
}

func (d *DB) commit(blks []*roothash.AnnotatedBlock) error {
	if len(blks) == 0 {
		return nil
	}

	return d.db.Update(func(tx *badger.Txn) error {
		meta, err := d.queryGetMetadata(tx)
		if err != nil {
			return err
		}

		for _, blk := range blks {
			rtID := blk.Block.Header.Namespace
			if !rtID.Equal(&meta.RuntimeID) {
				return fmt.Errorf("runtime mismatch (expected: %s got: %s)",
					meta.RuntimeID,
					rtID,
				)
			}

			if blk.Height < meta.LastConsensusHeight {
				return fmt.Errorf("commit at lower consensus height (current: %d wanted: %d)",
					meta.LastConsensusHeight,
					blk.Height,
				)
			}

			if blk.Block.Header.Round <= meta.LastRound && meta.LastConsensusHeight != 0 {
				return fmt.Errorf("commit at lower or equal round (current: %d wanted: %d)",
					meta.LastRound,
					blk.Block.Header.Round,
				)
			}

			if err := tx.Set(blockKeyFmt.Encode(blk.Block.Header.Round), cbor.Marshal(blk)); err != nil {
				return err
			}

			meta.LastRound = blk.Block.Header.Round
			if blk.Height > meta.LastConsensusHeight {
				meta.LastConsensusHeight = blk.Height
			}
		}
		return tx.Set(metadataKeyFmt.Encode(), cbor.Marshal(meta))
	})
}

func (d *DB) getBlock(round uint64) (*roothash.AnnotatedBlock, error) {
	var blk roothash.AnnotatedBlock
	txErr := d.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get(blockKeyFmt.Encode(round))
		switch err {
		case nil:
		case badger.ErrKeyNotFound:
			return roothash.ErrNotFound
		default:
			return err
		}

		return item.Value(func(val []byte) error {
			return cbor.UnmarshalTrusted(val, &blk)
		})
	})
	if txErr != nil {
		return nil, txErr
	}
	return &blk, nil
}

func (d *DB) getEarliestBlock() (*roothash.AnnotatedBlock, error) {
	var blk roothash.AnnotatedBlock
	txErr := d.db.View(func(tx *badger.Txn) error {
		prefix := blockKeyFmt.Encode()
		it := tx.NewIterator(badger.IteratorOptions{Prefix: prefix})
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			return item.Value(func(val []byte) error {
				return cbor.UnmarshalTrusted(val, &blk)
			})
		}
		return roothash.ErrNotFound
	})
	if txErr != nil {
		return nil, txErr
	}
	return &blk, nil
}

func (d *DB) getLastBlock() (*roothash.AnnotatedBlock, error) {
	var blk roothash.AnnotatedBlock
	txErr := d.db.View(func(tx *badger.Txn) error {
		meta, err := d.queryGetMetadata(tx)
		if err != nil {
			return err
		}

		item, err := tx.Get(blockKeyFmt.Encode(meta.LastRound))
		switch err {
		case nil:
		case badger.ErrKeyNotFound:
			return roothash.ErrNotFound
		default:
			return err
		}

		return item.Value(func(val []byte) error {
			return cbor.UnmarshalTrusted(val, &blk)
		})
	})
	if txErr != nil {
		return nil, txErr
	}
	return &blk, nil
}

func (d *DB) deleteBlock(round uint64) error {
	return d.db.Update(func(tx *badger.Txn) error {
		it := tx.NewIterator(badger.IteratorOptions{
			Prefix: blockKeyFmt.Encode(),
		})
		defer it.Close()

		it.Rewind()
		if !it.Valid() {
			return fmt.Errorf("db is empty")
		}
		item := it.Item()

		var blk roothash.AnnotatedBlock
		if err := item.Value(func(val []byte) error {
			return cbor.UnmarshalTrusted(val, &blk)
		}); err != nil {
			return fmt.Errorf("failed to unmarshal earliest block: %w", err)
		}

		if blk.Block.Header.Round != round {
			return fmt.Errorf("deleting non-earliest version (earliest: %d)", blk.Block.Header.Round)
		}

		return tx.Delete(item.KeyCopy(nil))
	})
}

func (d *DB) close() {
	d.gc.Stop()
	d.db.Close()
}
