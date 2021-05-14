package badger

import (
	"fmt"

	"github.com/dgraph-io/badger/v3"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// RenameNamespace changes the namespace specified in the database.
func RenameNamespace(cfg *api.Config, newNamespace common.Namespace) error {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/badger/rename"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}
	opts := commonConfigToBadgerOptions(cfg, db)

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	tx := db.db.NewTransactionAt(tsMetadata, true)
	defer tx.Discard()

	item, err := tx.Get(metadataKeyFmt.Encode())
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		// Nothing to rename.
		return nil
	default:
		return err
	}

	var meta metadata
	err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &meta.value)
	})
	if err != nil {
		return fmt.Errorf("failed to load database metadata: %w", err)
	}

	// Sanity checks.
	if meta.value.Version != dbVersion {
		return fmt.Errorf("incompatible database version (expected: %d got: %d)",
			dbVersion,
			meta.value.Version,
		)
	}
	if !meta.value.Namespace.Equal(&cfg.Namespace) {
		return fmt.Errorf("incompatible namespace (expected: %s got: %s)",
			cfg.Namespace,
			meta.value.Namespace,
		)
	}

	// Rename the namespace in database metadata.
	meta.value.Namespace = newNamespace
	if err = meta.save(tx); err != nil {
		return fmt.Errorf("failed to save database metadata: %w", err)
	}
	if err = tx.CommitAt(tsMetadata, nil); err != nil {
		return fmt.Errorf("failed to commit database metadata: %w", err)
	}

	return nil
}
