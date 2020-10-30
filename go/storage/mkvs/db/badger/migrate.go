package badger

import (
	"bytes"
	"fmt"
	"math"

	"github.com/dgraph-io/badger/v2"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	flushInterval = 5000

	maxTimestamp = math.MaxUint64
)

type migratorFactory func(db *badgerNodeDB, helper MigrationHelper) migration

var (
	// ErrVersionNotFound can be returned by the migration helper when the
	// relevant version can't be found in the history database.
	ErrVersionNotFound = fmt.Errorf("version not found")

	originVersions = map[uint64]migratorFactory{
		3: func(db *badgerNodeDB, helper MigrationHelper) migration {
			return &v4Migrator{
				meta:        v4MigratorMetadata{},
				db:          db,
				helper:      helper,
				flushRemain: flushInterval,
			}
		},
	}

	migrationMetaKeyFmt = keyformat.New(0xff)

	v3NodeKeyFmt                    = keyformat.New(0x00, &hash.Hash{})
	v3WriteLogKeyFmt                = keyformat.New(0x01, uint64(0), &hash.Hash{}, &hash.Hash{})
	v3RootsMetadataKeyFmt           = keyformat.New(0x02, uint64(0))
	v3RootUpdatedNodesKeyFmt        = keyformat.New(0x03, uint64(0), &hash.Hash{})
	v3MetadataKeyFmt                = keyformat.New(0x04)
	v3MultipartRestoreNodeLogKeyFmt = keyformat.New(0x05, &hash.Hash{})

	v4NodeKeyFmt                    = nodeKeyFmt // nolint: deadcode, varcheck, unused
	v4WriteLogKeyFmt                = writeLogKeyFmt
	v4RootsMetadataKeyFmt           = rootsMetadataKeyFmt
	v4RootUpdatedNodesKeyFmt        = rootUpdatedNodesKeyFmt
	v4MetadataKeyFmt                = metadataKeyFmt
	v4MultipartRestoreNodeLogKeyFmt = multipartRestoreNodeLogKeyFmt
	v4RootNodeKeyFmt                = rootNodeKeyFmt
)

type v3RootsMetadata struct {
	_ struct{} `cbor:",toarray"`

	Roots map[hash.Hash][]hash.Hash
}

type v4RootsMetadata = rootsMetadata

type v3UpdatedNode struct {
	_ struct{} `cbor:",toarray"` // nolint

	Removed bool
	Hash    hash.Hash
}

type v4UpdatedNode = updatedNode

// No change in metadata format between versions 3 and 4.
type v3SerializedMetadata = serializedMetadata

type v4SerializedMetadata = serializedMetadata // nolint: deadcode

type DisplayHelper interface {
	DisplayStepBegin(msg string)
	DisplayStepEnd(msg string)
	DisplayStep(msg string)
	DisplayProgress(msg string, current, total uint64)
}

type MigrationHelper interface {
	DisplayHelper
	GetRootForHash(root hash.Hash, version uint64) ([]node.Root, error)
}

type migration interface {
	Migrate() (uint64, error)
}

type migrationCommonMeta struct {
	// An item with this key should always exist in the metadata blob.
	// It is the original version of the database, before the migration started,
	// so the migration driver can choose the correct migration to resume with
	// even in cases where the database metadata key was already migrated.
	BaseDBVersion uint64 `json:"base_version"`
}

type v4MigratorMetadata struct {
	migrationCommonMeta

	InitComplete bool `json:"init_complete"`
	MetaComplete bool `json:"meta_complete"`

	MultipartActive bool   `json:"multipart_active"`
	LastKey         []byte `json:"last_key"`
	LastKeyVersion  uint64 `json:"last_key_version"`

	MetaCount        uint64 `json:"meta_count"`
	CurrentMetaCount uint64 `json:"current_meta_count"`
}

func (m *v4MigratorMetadata) load(db *badger.DB) error {
	txn := db.NewTransactionAt(tsMetadata, false)
	defer txn.Discard()

	item, err := txn.Get(migrationMetaKeyFmt.Encode())
	if err != nil {
		return err
	}

	return item.Value(func(data []byte) error {
		return cbor.Unmarshal(data, m)
	})
}

func (m *v4MigratorMetadata) save(batch *badger.WriteBatch) error {
	return batch.SetEntryAt(badger.NewEntry(
		migrationMetaKeyFmt.Encode(),
		cbor.Marshal(m),
	), tsMetadata)
}

func (m *v4MigratorMetadata) remove(batch *badger.WriteBatch) error {
	return batch.DeleteAt(migrationMetaKeyFmt.Encode(), tsMetadata)
}

type v4Migrator struct {
	db     *badgerNodeDB
	helper MigrationHelper

	readTxn     *badger.Txn
	changeBatch *badger.WriteBatch
	flushRemain int

	meta v4MigratorMetadata
	done bool
}

func (v4 *v4Migrator) flush(force bool) error {
	v4.flushRemain--
	if v4.flushRemain < 0 || force {
		v4.flushRemain = flushInterval
		if v4.done {
			if err := v4.meta.remove(v4.changeBatch); err != nil {
				return fmt.Errorf("error clearing progress: %w", err)
			}
		} else {
			if err := v4.meta.save(v4.changeBatch); err != nil {
				return fmt.Errorf("error saving progress: %w", err)
			}
		}
		if err := v4.changeBatch.Flush(); err != nil {
			return fmt.Errorf("error committing database state: %w", err)
		}
		v4.changeBatch = v4.db.db.NewWriteBatchAt(maxTimestamp)
	}
	return nil
}

// This is only usable once rootsMetadataKeyFmt keys have been migrated!
func (v4 *v4Migrator) getRootType(rh hash.Hash, version uint64) ([]node.RootType, error) {
	roots, err := v4.helper.GetRootForHash(rh, version)
	if err == nil && len(roots) > 0 {
		rootTypes := make([]node.RootType, len(roots))
		for i, root := range roots {
			rootTypes[i] = root.Type
		}
		return rootTypes, nil
	}

	// If not directly discoverable, try traversing finalized roots metadata.
	meta, err := loadRootsMetadata(v4.readTxn, version)
	if err != nil {
		return nil, err
	}

	found := map[node.RootType]struct{}{}
	for root, chain := range meta.Roots {
		h := root.Hash()
		if h.Equal(&rh) {
			found[root.Type()] = struct{}{}
		}
		for _, droot := range chain {
			h := droot.Hash()
			if h.Equal(&rh) {
				found[droot.Type()] = struct{}{}
			}
		}
	}
	ret := make([]node.RootType, 0, len(found))
	for typ := range found {
		ret = append(ret, typ)
	}

	return ret, nil
}

func (v4 *v4Migrator) keyMetadata(item *badger.Item) error {
	var meta3 v3SerializedMetadata
	err := item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &meta3)
	})
	if err != nil {
		return fmt.Errorf("error decoding database metadata: %w", err)
	}

	meta4 := meta3
	meta4.Version = 4

	entry := badger.NewEntry(
		v4MetadataKeyFmt.Encode(),
		cbor.Marshal(meta4),
	)
	err = v4.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("error storing updated database metadata: %w", err)
	}

	return nil
}

func (v4 *v4Migrator) keyRootsMetadata(item *badger.Item) error { // nolint: gocyclo
	if item.IsDeletedOrExpired() {
		// Roots metadata keys are always at tsMetadata.
		return nil
	}

	var version uint64
	if !v3RootsMetadataKeyFmt.Decode(item.Key(), &version) {
		return fmt.Errorf("error decoding roots metadata key")
	}

	var rootsMeta v3RootsMetadata
	err := item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &rootsMeta)
	})
	if err != nil {
		return fmt.Errorf("error deserializing roots metadata: %w", err)
	}

	// Propagate type information throughout the derived root chains.
	plainRoots := map[hash.Hash]map[node.RootType]struct{}{}
	for root, chain := range rootsMeta.Roots {
		plainRoots[root] = map[node.RootType]struct{}{}
		for _, droot := range chain {
			plainRoots[droot] = map[node.RootType]struct{}{}
		}
	}

	remaining := len(plainRoots)
	for root := range plainRoots {
		var full []node.Root
		full, err = v4.helper.GetRootForHash(root, version)
		if err == nil && len(full) > 0 {
			for _, r := range full {
				plainRoots[root][r.Type] = struct{}{}
			}
			remaining--
		}
		if err != nil && err != ErrVersionNotFound {
			return fmt.Errorf("error checking root %v for version %v: %w", root, version, err)
		}
		// If the root isn't found, we'll probably get stuck in the loop below and delete this key.
	}

	for remaining > 0 {
		preLoop := remaining
		for root, chain := range rootsMeta.Roots {
			types := map[node.RootType]struct{}{}
			all := append([]hash.Hash{root}, chain...)
			for _, droot := range all {
				if dtypes, ok := plainRoots[droot]; ok && len(dtypes) > 0 {
					for typ := range dtypes {
						types[typ] = struct{}{}
					}
				}
			}

			if len(types) > 0 {
				for _, root := range all {
					if len(plainRoots[root]) == 0 {
						plainRoots[root] = types
						remaining--
					}
				}
			}
		}

		if remaining == preLoop {
			// Can't find all versions, so probably for some roots the GetRootForHash call above
			// failed with an ErrNotFound; this key must be stale.
			err = v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version())
			if err != nil {
				return fmt.Errorf("can't delete stale roots metadata key for version %v: %w", version, err)
			}
			return nil
		}
	}

	// Create root typing keys.
	for h, types := range plainRoots {
		for t := range types {
			th := typedHashFromParts(t, h)
			entry := badger.NewEntry(
				v4RootNodeKeyFmt.Encode(&th),
				[]byte{},
			)
			if err = v4.changeBatch.SetEntryAt(entry, versionToTs(version)); err != nil {
				return fmt.Errorf("error creating root typing key: %w", err)
			}
		}
	}

	// Build new roots structure.
	var newRoots v4RootsMetadata
	newRoots.Roots = map[typedHash][]typedHash{}
	for root, chain := range rootsMeta.Roots {
		for typ := range plainRoots[root] {
			arr := make([]typedHash, 0, len(chain))
			for _, droot := range chain {
				th := typedHashFromParts(typ, droot)
				arr = append(arr, th)
			}
			th := typedHashFromParts(typ, root)
			newRoots.Roots[th] = arr
		}
	}

	err = v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version())
	if err != nil {
		return fmt.Errorf("error removing old root metadata: %w", err)
	}
	entry := badger.NewEntry(v4RootsMetadataKeyFmt.Encode(&version), cbor.Marshal(newRoots))
	if err = v4.changeBatch.SetEntryAt(entry, item.Version()); err != nil {
		return fmt.Errorf("error storing updated root metadata: %w", err)
	}

	return nil
}

func (v4 *v4Migrator) keyWriteLog(item *badger.Item) error {
	var version uint64
	var h1, h2 hash.Hash
	var th1, th2 typedHash
	if !v3WriteLogKeyFmt.Decode(item.Key(), &version, &h1, &h2) {
		return fmt.Errorf("error decoding writelog key")
	}

	types, err := v4.getRootType(h1, version)
	if err != nil {
		return fmt.Errorf("error getting type for writelog root %v:%v: %w", h1, version, err)
	}
	if len(types) == 0 {
		// Root doesn't exist anymore, so this writelog is probably stale
		// and shouldn't exist anymore.
		err = v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version())
		if err != nil {
			return fmt.Errorf("can't delete stale writelog for root %v:%v: %w", h1, version, err)
		}
		return nil
	}

	err = v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version())
	if err != nil {
		return fmt.Errorf("error removing old writelog key: %w", err)
	}

	var val []byte
	_ = item.Value(func(data []byte) error {
		val = data
		return nil
	})

	for _, t1 := range types {
		th1.FromParts(t1, h1)
		th2.FromParts(t1, h2)
		key := v4WriteLogKeyFmt.Encode(&version, &th1, &th2)

		if item.IsDeletedOrExpired() {
			err = v4.changeBatch.DeleteAt(key, item.Version())
			if err != nil {
				return fmt.Errorf("error setting removed flag for writelog key: %w", err)
			}
		} else {
			entry := badger.NewEntry(key, val)
			err = v4.changeBatch.SetEntryAt(entry, item.Version())
			if err != nil {
				return fmt.Errorf("error setting updated writelog key: %w", err)
			}
		}
	}

	return nil
}

func (v4 *v4Migrator) keyRootUpdatedNodes(item *badger.Item) error {
	var version uint64
	var h1 hash.Hash
	if !v3RootUpdatedNodesKeyFmt.Decode(item.Key(), &version, &h1) {
		return fmt.Errorf("error decoding root updated nodes key")
	}

	types, err := v4.getRootType(h1, version)
	if err != nil || len(types) == 0 {
		return fmt.Errorf("error getting root %v:%v for updated nodes list: %w", h1, version, err)
	}
	err = v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version())
	if err != nil {
		return fmt.Errorf("error deleting old nodes nodes list for root %v: %w", h1, err)
	}
	if item.IsDeletedOrExpired() {
		for _, typ := range types {
			th := typedHashFromParts(typ, h1)
			key := v4RootUpdatedNodesKeyFmt.Encode(version, &th)
			if err = v4.changeBatch.DeleteAt(key, item.Version()); err != nil {
				return fmt.Errorf("error transforming removed updated nodes list for root %v: %w", th, err)
			}
		}
		return nil
	}

	var oldUpdatedNodes []v3UpdatedNode
	err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &oldUpdatedNodes)
	})
	if err != nil {
		return fmt.Errorf("error decoding updated nodes list for root %v:%v: %w", h1, version, err)
	}

	newUpdatedNodes := make([]v4UpdatedNode, 0, len(oldUpdatedNodes))
	for _, up := range oldUpdatedNodes {
		newUpdatedNodes = append(newUpdatedNodes, v4UpdatedNode{
			Removed: up.Removed,
			Hash:    up.Hash,
		})
	}

	for _, typ := range types {
		th := typedHashFromParts(typ, h1)

		if v4.meta.MultipartActive {
			entry := badger.NewEntry(
				v4MultipartRestoreNodeLogKeyFmt.Encode(&th),
				[]byte{},
			)
			if err = v4.changeBatch.SetEntryAt(entry, versionToTs(version)); err != nil {
				return fmt.Errorf("error setting multipart marker for root %v: %w", th, err)
			}
		}
		rootEntry := badger.NewEntry(
			rootNodeKeyFmt.Encode(&th),
			[]byte{},
		)
		if err = v4.changeBatch.SetEntryAt(rootEntry, versionToTs(version)); err != nil {
			return fmt.Errorf("error setting root marker for root %v: %w", th, err)
		}

		entry := badger.NewEntry(
			v4RootUpdatedNodesKeyFmt.Encode(version, &th),
			cbor.Marshal(newUpdatedNodes),
		)
		err = v4.changeBatch.SetEntryAt(entry, item.Version())
		if err != nil {
			return fmt.Errorf("error storing updated nodes list for root %v: %w", th, err)
		}
	}

	return nil
}

func (v4 *v4Migrator) keyMultipartRestoreNodeLog(item *badger.Item) error {
	if item.IsDeletedOrExpired() {
		// These keys are all at tsMetadata.
		return nil
	}

	var h hash.Hash
	if !v3MultipartRestoreNodeLogKeyFmt.Decode(item.Key(), &h) {
		return fmt.Errorf("error decoding multipart restore key")
	}

	if err := v4.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version()); err != nil {
		return fmt.Errorf("can't delete old multipart restore log key for %v: %w", h, err)
	}
	th := typedHashFromParts(node.RootTypeInvalid, h)
	entry := badger.NewEntry(
		v4MultipartRestoreNodeLogKeyFmt.Encode(&th),
		[]byte{},
	)
	if err := v4.changeBatch.SetEntryAt(entry, item.Version()); err != nil {
		return fmt.Errorf("can't create new multipart restore log key for %v: %w", h, err)
	}

	return nil
}

func (v4 *v4Migrator) migrateMeta() error {
	v4.helper.DisplayStepBegin("migrating storage roots and metadata")

	keyOrder := []byte{
		v3MetadataKeyFmt.Prefix(),
		v3RootsMetadataKeyFmt.Prefix(),
		v3WriteLogKeyFmt.Prefix(),
		v3RootUpdatedNodesKeyFmt.Prefix(),
		v3MultipartRestoreNodeLogKeyFmt.Prefix(),
		// Other keys don't need to be migrated.
	}
	if len(v4.meta.LastKey) == 0 {
		v4.meta.LastKey = []byte{keyOrder[0]}
		v4.meta.LastKeyVersion = maxTimestamp
		// LastKey records the last _already processed_ key, so
		// if we're only just starting up, the first key we see
		// won't have been processed yet.
	}

	keyNexts := map[byte]byte{}
	for i := 0; i < len(keyOrder)-1; i++ {
		keyNexts[keyOrder[i]] = keyOrder[i+1]
	}

	keyFuncs := map[byte]func(item *badger.Item) error{
		v3MetadataKeyFmt.Prefix():                v4.keyMetadata,
		v3RootsMetadataKeyFmt.Prefix():           v4.keyRootsMetadata,
		v3WriteLogKeyFmt.Prefix():                v4.keyWriteLog,
		v3RootUpdatedNodesKeyFmt.Prefix():        v4.keyRootUpdatedNodes,
		v3MultipartRestoreNodeLogKeyFmt.Prefix(): v4.keyMultipartRestoreNodeLog,
	}

	opts := badger.DefaultIteratorOptions
	opts.AllVersions = true
	it := v4.readTxn.NewIterator(opts)
	defer func() {
		v4.readTxn.Discard()
		v4.readTxn = v4.db.db.NewTransactionAt(maxTimestamp, false)
	}()
	defer func() {
		it.Close()
	}()

	currentKey := v4.meta.LastKey[0]
	var keyOk bool
	for {
		it.Rewind()
		it.Seek(v4.meta.LastKey)
		for ; it.Valid(); it.Next() {
			if bytes.Equal(v4.meta.LastKey, it.Item().Key()) && it.Item().Version() >= v4.meta.LastKeyVersion {
				continue
			}
			if it.Item().Key()[0] != currentKey {
				break
			}

			if err := keyFuncs[currentKey](it.Item()); err != nil {
				return err
			}

			v4.meta.CurrentMetaCount++
			v4.helper.DisplayProgress("updated keys", v4.meta.CurrentMetaCount, v4.meta.MetaCount)
			v4.meta.LastKey = it.Item().KeyCopy(v4.meta.LastKey)
			v4.meta.LastKeyVersion = it.Item().Version()

			// Save progress.
			if err := v4.flush(false); err != nil {
				return err
			}
		}

		// Force flush everything.
		if err := v4.flush(true); err != nil {
			return err
		}
		it.Close()
		v4.readTxn.Discard()
		v4.readTxn = v4.db.db.NewTransactionAt(maxTimestamp, false)
		it = v4.readTxn.NewIterator(badger.DefaultIteratorOptions)

		currentKey, keyOk = keyNexts[currentKey]
		if !keyOk {
			break
		}
		v4.meta.LastKey = []byte{currentKey}
		v4.meta.LastKeyVersion = maxTimestamp
	}

	return nil
}

func (v4 *v4Migrator) Migrate() (rversion uint64, rerr error) {
	v4.readTxn = v4.db.db.NewTransactionAt(maxTimestamp, false)
	defer func() {
		// readTxn will change throughout the process, don't
		// bind the defer to a particular instance.
		v4.readTxn.Discard()
	}()
	v4.changeBatch = v4.db.db.NewWriteBatchAt(maxTimestamp)
	defer func() {
		// changeBatch will change throughout the process, don't
		// bind the defer to a particular instance.
		v4.changeBatch.Cancel()
	}()

	// Load migration metadata and set up saving on function return.
	err := v4.meta.load(v4.db.db)
	if err != nil && err != badger.ErrKeyNotFound {
		return 0, err
	}
	v4.meta.BaseDBVersion = 3

	// Count keys first, so we can report some sensible progress to the user.
	// Badger says this should be fast.
	if !v4.meta.InitComplete {
		v4.helper.DisplayStepBegin("scanning database")
		v4.meta.MetaCount = 0
		func() {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			opts.AllVersions = true
			it := v4.readTxn.NewIterator(opts)
			defer it.Close()
			it.Rewind()
			it.Seek([]byte{v3WriteLogKeyFmt.Prefix()})
			for ; it.Valid(); it.Next() {
				prefix := it.Item().Key()[0]
				if prefix == v3MultipartRestoreNodeLogKeyFmt.Prefix() {
					v4.meta.MultipartActive = true
				}
				if prefix != v3NodeKeyFmt.Prefix() && prefix != v3MultipartRestoreNodeLogKeyFmt.Prefix() {
					v4.meta.MetaCount++
				}
			}
		}()
		v4.meta.InitComplete = true
		v4.helper.DisplayStepEnd(fmt.Sprintf("%v keys to migrate", v4.meta.MetaCount))
	}

	// Migrate!

	if !v4.meta.MetaComplete {
		if err := v4.migrateMeta(); err != nil {
			return 0, err
		}
		v4.meta.MetaComplete = true
		v4.meta.LastKey = []byte{}
		v4.meta.LastKeyVersion = maxTimestamp
		if err := v4.flush(true); err != nil {
			return 0, fmt.Errorf("error migrating metadata: %w", err)
		}
	}

	// All done, flush and clean up. The metadata blob will be removed
	// in the defer handler.
	v4.done = true
	if err := v4.flush(true); err != nil {
		return 0, err
	}
	return 4, nil
}

// Migrate performs forward migrations between database versions.
func Migrate(cfg *api.Config, helper MigrationHelper) (uint64, error) {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/badger/migrate"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}
	opts := commonConfigToBadgerOptions(cfg, db)

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return 0, fmt.Errorf("mkvs/badger/migrate: failed to open database: %w", err)
	}
	defer db.Close()

	// Make sure that we can discard any deleted/invalid metadata.
	db.db.SetDiscardTs(tsMetadata)

	// Load metadata.
	lastVersion, err := func() (uint64, error) {
		tx := db.db.NewTransactionAt(tsMetadata, false)
		defer tx.Discard()

		// Check if there was already a migration in progress.
		var migMeta migrationCommonMeta
		item, rerr := tx.Get(migrationMetaKeyFmt.Encode())
		if rerr == nil {
			rerr = item.Value(func(data []byte) error {
				return cbor.UnmarshalTrusted(data, &migMeta)
			})
			if rerr != nil {
				return 0, fmt.Errorf("corrupt migration metadata: %w", rerr)
			}
			return migMeta.BaseDBVersion, nil
		}

		// Otherwise try getting the current db version from its metadata.
		item, rerr = tx.Get(v3MetadataKeyFmt.Encode())
		if rerr != nil {
			return 0, fmt.Errorf("can't get existing database metadata: %w", rerr)
		}

		var meta metadata

		rerr = item.Value(func(data []byte) error {
			return cbor.UnmarshalTrusted(data, &meta.value)
		})
		if rerr != nil {
			return 0, fmt.Errorf("corrupt database metadata: %w", rerr)
		}

		return meta.value.Version, nil
	}()
	if err != nil {
		return 0, fmt.Errorf("mkvs/badger/migrate: error probing current database version: %w", err)
	}

	// Main upgrade loop.
	for lastVersion != dbVersion {
		migratorFactory := originVersions[lastVersion]
		if migratorFactory == nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: unsupported version %d", lastVersion)
		}
		migrator := migratorFactory(db, helper)

		newVersion, err := migrator.Migrate()
		if err != nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: error while migrating from version %d: %w", lastVersion, err)
		}
		lastVersion = newVersion
	}

	return lastVersion, nil
}
