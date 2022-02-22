package badger

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/dgraph-io/badger/v3"

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
		4: func(db *badgerNodeDB, helper MigrationHelper) migration {
			return &v5Migrator{
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

	v4NodeKeyFmt                    = nodeKeyFmt
	v4WriteLogKeyFmt                = writeLogKeyFmt
	v4RootsMetadataKeyFmt           = rootsMetadataKeyFmt
	v4RootUpdatedNodesKeyFmt        = rootUpdatedNodesKeyFmt
	v4MetadataKeyFmt                = metadataKeyFmt
	v4MultipartRestoreNodeLogKeyFmt = multipartRestoreNodeLogKeyFmt
	v4RootNodeKeyFmt                = rootNodeKeyFmt
	v4NodeVersionSize               = 8

	v5NodeKeyFmt             = nodeKeyFmt
	v5WriteLogKeyFmt         = writeLogKeyFmt
	v5MetadataKeyFmt         = metadataKeyFmt
	v5RootsMetadataKeyFmt    = rootsMetadataKeyFmt
	v5RootUpdatedNodesKeyFmt = rootUpdatedNodesKeyFmt
	v5RootNodeKeyFmt         = rootNodeKeyFmt
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

type v4SerializedMetadata = serializedMetadata

type DisplayHelper interface {
	Display(msg string)
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
	// TargetVersion returns the version this migration will migrate to.
	TargetVersion() uint64

	// Migrate performs the migration, returning the target version.
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

	v4.helper.DisplayStepEnd("done")

	return nil
}

func (v4 *v4Migrator) TargetVersion() uint64 {
	return 4
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

	// Load migration metadata.
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

	// All done, flush and clean up.
	v4.done = true
	if err := v4.flush(true); err != nil {
		return 0, err
	}
	return 4, nil
}

type v5MigratedRoot struct {
	Hash    typedHash `json:"hash"`
	Version uint64    `json:"version"`
}

type v5MigratorMetadata struct {
	migrationCommonMeta

	LastMigratedVersion *uint64                      `json:"last_migrated_version"`
	LastMigratedRoots   map[typedHash]v5MigratedRoot `json:"last_migrated_roots"`
	LastPrunedVersion   *uint64                      `json:"last_pruned_version"`
}

func (m *v5MigratorMetadata) load(db *badger.DB) error {
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

func (m *v5MigratorMetadata) save(batch *badger.WriteBatch) error {
	return batch.SetEntryAt(badger.NewEntry(
		migrationMetaKeyFmt.Encode(),
		cbor.Marshal(m),
	), tsMetadata)
}

func (m *v5MigratorMetadata) remove(batch *badger.WriteBatch) error {
	return batch.DeleteAt(migrationMetaKeyFmt.Encode(), tsMetadata)
}

type v5Key struct {
	key []byte
	ts  uint64
}

type v5Migrator struct {
	db     *badgerNodeDB
	helper MigrationHelper

	readTxn     *badger.Txn
	changeBatch *badger.WriteBatch
	flushRemain int

	deleteKeys []v5Key

	meta v5MigratorMetadata
	done bool
}

func (v5 *v5Migrator) flush(force bool) error {
	v5.flushRemain--
	if v5.flushRemain < 0 || force {
		v5.flushRemain = flushInterval
		if v5.done {
			if err := v5.meta.remove(v5.changeBatch); err != nil {
				return fmt.Errorf("error clearing progress: %w", err)
			}
		} else {
			if err := v5.meta.save(v5.changeBatch); err != nil {
				return fmt.Errorf("error saving progress: %w", err)
			}
		}
		if err := v5.changeBatch.Flush(); err != nil {
			return fmt.Errorf("error committing database state: %w", err)
		}
		v5.changeBatch = v5.db.db.NewWriteBatchAt(maxTimestamp)
	}
	return nil
}

func (v5 *v5Migrator) unmarshalV4InternalNode(n *node.InternalNode, data []byte) (int, error) {
	if len(data) < 1+v4NodeVersionSize+node.DepthSize+1 {
		return 0, node.ErrMalformedNode
	}

	pos := 0
	if data[pos] != node.PrefixInternalNode {
		return 0, node.ErrMalformedNode
	}
	pos++

	// Skip version field.
	pos += v4NodeVersionSize

	if _, err := n.LabelBitLength.UnmarshalBinary(data[pos:]); err != nil {
		return 0, fmt.Errorf("mkvs: failed to unmarshal LabelBitLength: %w", err)
	}
	labelLen := n.LabelBitLength.ToBytes()
	pos += node.DepthSize
	if pos+labelLen > len(data) {
		return 0, node.ErrMalformedNode
	}

	n.Label = make(node.Key, labelLen)
	copy(n.Label, data[pos:pos+labelLen])
	pos += labelLen
	if pos >= len(data) {
		return 0, node.ErrMalformedNode
	}

	if data[pos] == node.PrefixNilNode {
		n.LeafNode = nil
		pos++
	} else {
		leafNode := node.LeafNode{}
		var leafNodeBinarySize int
		var err error
		if leafNodeBinarySize, err = v5.unmarshalV4LeafNode(&leafNode, data[pos:]); err != nil {
			return 0, fmt.Errorf("mkvs: failed to unmarshal leaf node: %w", err)
		}
		n.LeafNode = &node.Pointer{Clean: true, Hash: leafNode.Hash, Node: &leafNode}
		pos += leafNodeBinarySize
	}

	var leftHash hash.Hash
	if err := leftHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
		return 0, fmt.Errorf("mkvs: failed to unmarshal left hash: %w", err)
	}
	pos += hash.Size
	var rightHash hash.Hash
	if err := rightHash.UnmarshalBinary(data[pos : pos+hash.Size]); err != nil {
		return 0, fmt.Errorf("mkvs: failed to unmarshal right hash: %w", err)
	}
	pos += hash.Size

	if leftHash.IsEmpty() {
		n.Left = nil
	} else {
		n.Left = &node.Pointer{Clean: true, Hash: leftHash}
	}

	if rightHash.IsEmpty() {
		n.Right = nil
	} else {
		n.Right = &node.Pointer{Clean: true, Hash: rightHash}
	}

	n.UpdateHash()

	n.Clean = true

	return pos, nil
}

func (v5 *v5Migrator) unmarshalV4LeafNode(n *node.LeafNode, data []byte) (int, error) {
	if len(data) < 1+v4NodeVersionSize+node.DepthSize+node.ValueLengthSize || data[0] != node.PrefixLeafNode {
		return 0, node.ErrMalformedNode
	}

	pos := 1
	// Skip version field.
	pos += v4NodeVersionSize

	var key node.Key
	keySize, err := key.SizedUnmarshalBinary(data[pos:])
	if err != nil {
		return 0, err
	}
	pos += keySize
	if pos+node.ValueLengthSize > len(data) {
		return 0, node.ErrMalformedNode
	}

	valueSize := int(binary.LittleEndian.Uint32(data[pos : pos+node.ValueLengthSize]))
	pos += node.ValueLengthSize
	if pos+valueSize > len(data) {
		return 0, node.ErrMalformedNode
	}

	value := make([]byte, valueSize)
	copy(value, data[pos:pos+valueSize])
	pos += valueSize

	n.Clean = true
	n.Key = key
	n.Value = value

	n.UpdateHash()

	return pos, nil
}

func (v5 *v5Migrator) migrateNode(h hash.Hash, version uint64) (*hash.Hash, error) {
	item, err := v5.readTxn.Get(v4NodeKeyFmt.Encode(&h))
	if err != nil {
		return nil, fmt.Errorf("error loading node %s: %w", h, err)
	}
	raw, err := item.ValueCopy(nil)
	if err != nil {
		return nil, fmt.Errorf("error loading node %s: %w", h, err)
	}

	// Decode node type.
	var (
		newHash hash.Hash
		newNode []byte
	)
	switch raw[0] {
	case node.PrefixInternalNode:
		var n node.InternalNode
		_, err = v5.unmarshalV4InternalNode(&n, raw)
		if err != nil {
			return nil, fmt.Errorf("error decoding internal node %s: %w", h, err)
		}

		// Migrate children.
		for _, child := range []*node.Pointer{n.Left, n.Right} {
			if child == nil {
				continue
			}
			var nh *hash.Hash
			nh, err = v5.migrateNode(child.Hash, version)
			if err != nil {
				return nil, err
			}
			child.Hash = *nh
		}
		n.UpdateHash()
		newHash = n.GetHash()
		newNode, _ = n.MarshalBinary()
	case node.PrefixLeafNode:
		var n node.LeafNode
		_, err = v5.unmarshalV4LeafNode(&n, raw)
		if err != nil {
			return nil, fmt.Errorf("error decoding leaf node %s: %w", h, err)
		}
		newHash = n.GetHash()
		newNode, _ = n.MarshalBinary()
	default:
		return nil, fmt.Errorf("unknown node type for node %s: 0x%02x", h, raw[0])
	}

	// Store node under the new hash.
	entry := badger.NewEntry(v5NodeKeyFmt.Encode(&newHash), newNode)
	err = v5.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return nil, fmt.Errorf("error setting updated node key: %w", err)
	}
	// Queue removal of any old nodes.
	v5.deleteKeys = append(v5.deleteKeys, v5Key{key: item.KeyCopy(nil), ts: item.Version()})

	return &newHash, nil
}

func (v5 *v5Migrator) migrateWriteLog(oldSrcRoot, oldDstRoot, newSrcRoot typedHash, newDstRoot v5MigratedRoot) error {
	item, err := v5.readTxn.Get(v4WriteLogKeyFmt.Encode(newDstRoot.Version, &oldDstRoot, &oldSrcRoot))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		// Write log does not exist.
		return nil
	default:
		return fmt.Errorf("error reading write log for %d: %s -> %s: %w", newDstRoot.Version, oldSrcRoot, oldDstRoot, err)
	}

	var value []byte
	_ = item.Value(func(data []byte) error {
		value = data
		return nil
	})

	entry := badger.NewEntry(
		v5WriteLogKeyFmt.Encode(newDstRoot.Version, &newDstRoot.Hash, &newSrcRoot),
		value,
	)
	err = v5.changeBatch.SetEntryAt(entry, item.Version())
	if err != nil {
		return fmt.Errorf("error setting updated write log key: %w", err)
	}
	// Make sure old write log is removed.
	v5.deleteKeys = append(v5.deleteKeys, v5Key{key: item.KeyCopy(nil), ts: item.Version()})

	return nil
}

func (v5 *v5Migrator) migrateVersion(version uint64, migratedRoots map[typedHash]v5MigratedRoot) (bool, error) {
	defer func() {
		v5.readTxn.Discard()
		v5.readTxn = v5.db.db.NewTransactionAt(maxTimestamp, false)
	}()

	v5.helper.DisplayStep(fmt.Sprintf("migrating version %d", version))

	var roots v4RootsMetadata
	item, err := v5.readTxn.Get(v4RootsMetadataKeyFmt.Encode(version))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		// Version does not exist.
		return false, nil
	default:
		return false, fmt.Errorf("error reading roots metadata for version %d: %w", version, err)
	}
	err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &roots)
	})
	if err != nil {
		return false, fmt.Errorf("error decoding roots metadata for version %d: %w", version, err)
	}

	newRoots := make(map[typedHash][]typedHash)
	for root := range roots.Roots {
		// Migrate the tree (if not empty).
		var newRootHash hash.Hash
		if rootHash := root.Hash(); !rootHash.IsEmpty() {
			var nrh *hash.Hash
			nrh, err = v5.migrateNode(rootHash, version)
			if err != nil {
				return false, fmt.Errorf("error migrating root %s: %w", root, err)
			}
			newRootHash = *nrh
		} else {
			newRootHash.Empty()
		}

		newRoot := typedHashFromParts(root.Type(), newRootHash)
		newRoots[newRoot] = []typedHash{}
		migratedRoots[root] = v5MigratedRoot{Hash: newRoot, Version: version}

		// Check for a write log from empty root.
		var emptyHash hash.Hash
		emptyHash.Empty()
		emptyRoot := typedHashFromParts(root.Type(), emptyHash)

		if err = v5.migrateWriteLog(emptyRoot, root, emptyRoot, migratedRoots[root]); err != nil {
			return false, err
		}

		// Add root node type info.
		entry := badger.NewEntry(v5RootNodeKeyFmt.Encode(&newRoot), []byte{})
		err = v5.changeBatch.SetEntryAt(entry, versionToTs(version))
		if err != nil {
			return false, fmt.Errorf("error setting updated root node key: %w", err)
		}
		// Make sure old root node type info is removed.
		v5.deleteKeys = append(v5.deleteKeys, v5Key{key: v5RootNodeKeyFmt.Encode(&root), ts: versionToTs(version)})

		// Remove updated nodes.
		item, err = v5.readTxn.Get(v4RootUpdatedNodesKeyFmt.Encode(version, &root))
		switch err {
		case nil:
			// Add empty list, assume nothing needs to be pruned.
			entry = badger.NewEntry(v5RootUpdatedNodesKeyFmt.Encode(version, &newRoot), cbor.Marshal([]updatedNode{}))
			err = v5.changeBatch.SetEntryAt(entry, versionToTs(version))
			if err != nil {
				return false, fmt.Errorf("error setting updated root node key: %w", err)
			}
			// Remove.
			v5.deleteKeys = append(v5.deleteKeys, v5Key{key: item.KeyCopy(nil), ts: versionToTs(version)})
		case badger.ErrKeyNotFound:
			// Nothing to do -- finalized version.
		default:
			return false, fmt.Errorf("error reading updated nodes metadata: %w", err)
		}

		v5.helper.Display(fmt.Sprintf("migrated root %s -> %s", root, newRoot))
	}
	for root, dstRoots := range roots.Roots {
		newRoot := migratedRoots[root].Hash

		for _, dstRoot := range dstRoots {
			migratedRoot, exists := migratedRoots[dstRoot]
			if !exists {
				return false, fmt.Errorf("internal error: derived root %s not migrated", dstRoot)
			}
			newRoots[newRoot] = append(newRoots[newRoot], migratedRoot.Hash)

			// Migrate write log.
			if err = v5.migrateWriteLog(root, dstRoot, newRoot, migratedRoot); err != nil {
				return false, err
			}
		}
	}
	// Remove any migrated roots that are not in this version.
	for root, meta := range migratedRoots {
		if meta.Version != version {
			delete(migratedRoots, root)
		}
	}

	// Update roots metadata.
	roots.Roots = newRoots
	entry := badger.NewEntry(v5RootsMetadataKeyFmt.Encode(version), cbor.Marshal(roots))
	err = v5.changeBatch.SetEntryAt(entry, tsMetadata)
	if err != nil {
		return false, fmt.Errorf("error setting updated roots metadata key: %w", err)
	}

	// Save progress.
	v5.meta.LastMigratedRoots = migratedRoots
	v5.meta.LastMigratedVersion = &version

	if err = v5.flush(false); err != nil {
		return false, err
	}

	// Delete any pending keys.
	for _, k := range v5.deleteKeys {
		if err = v5.changeBatch.DeleteAt(k.key, k.ts); err != nil {
			return false, fmt.Errorf("can't delete old key %x: %w", k.key, err)
		}
	}
	v5.deleteKeys = nil

	return true, nil
}

func (v5 *v5Migrator) maybePruneNode(h hash.Hash, version uint64) error {
	item, err := v5.readTxn.Get(v4NodeKeyFmt.Encode(&h))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		// Node was already pruned (could be shared with some root in the same version).
		return nil
	default:
		return fmt.Errorf("error loading node %s: %w", h, err)
	}
	raw, err := item.ValueCopy(nil)
	if err != nil {
		return fmt.Errorf("error loading node %s: %w", h, err)
	}

	// Decode node type.
	switch raw[0] {
	case node.PrefixInternalNode:
		var n node.InternalNode
		_, err = v5.unmarshalV4InternalNode(&n, raw)
		if err != nil {
			return fmt.Errorf("error decoding internal node %s: %w", h, err)
		}

		// Maybe prune children.
		for _, child := range []*node.Pointer{n.Left, n.Right} {
			if child == nil {
				continue
			}
			err = v5.maybePruneNode(child.Hash, version)
			if err != nil {
				return err
			}
		}
	case node.PrefixLeafNode:
	default:
		return fmt.Errorf("unknown node type for node %s: 0x%02x", h, raw[0])
	}

	if tsToVersion(item.Version()) == version {
		if err = v5.changeBatch.DeleteAt(item.KeyCopy(nil), item.Version()); err != nil {
			return fmt.Errorf("error pruning node %s: %w", h, err)
		}
	}
	return nil
}

func (v5 *v5Migrator) pruneVersion(version uint64) error {
	defer func() {
		v5.readTxn.Discard()
		v5.readTxn = v5.db.db.NewTransactionAt(maxTimestamp, false)
	}()

	// Remove all roots in version.
	var rootsMeta v4RootsMetadata
	item, err := v5.readTxn.Get(v4RootsMetadataKeyFmt.Encode(version))
	switch err {
	case nil:
	case badger.ErrKeyNotFound:
		// Version does not exist.
		return nil
	default:
		return fmt.Errorf("error reading roots metadata for version %d: %w", version, err)
	}
	err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &rootsMeta)
	})
	if err != nil {
		return fmt.Errorf("error decoding roots metadata for version %d: %w", version, err)
	}

	for rootHash, derivedRoots := range rootsMeta.Roots {
		if len(derivedRoots) > 0 {
			// Not a lone root.
			continue
		}
		rh := rootHash.Hash()
		if rh.IsEmpty() {
			continue
		}

		if err = v5.maybePruneNode(rh, version); err != nil {
			return fmt.Errorf("error pruning root %s: %w", rootHash, err)
		}

		if err = v5.changeBatch.DeleteAt(rootNodeKeyFmt.Encode(&rootHash), versionToTs(version)); err != nil {
			return err
		}
	}

	// Delete roots metadata.
	if err = v5.changeBatch.DeleteAt(rootsMetadataKeyFmt.Encode(version), versionToTs(version)); err != nil {
		return fmt.Errorf("failed to remove roots metadata: %w", err)
	}

	// Prune all write logs in version.
	prefix := v4WriteLogKeyFmt.Encode(version)
	it := v5.readTxn.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		if err = v5.changeBatch.DeleteAt(it.Item().KeyCopy(nil), it.Item().Version()); err != nil {
			return fmt.Errorf("error pruning writelog: %w", err)
		}
	}

	// Save progress.
	v5.meta.LastPrunedVersion = &version

	if err = v5.flush(false); err != nil {
		return err
	}

	return nil
}

func (v5 *v5Migrator) pruneWriteLog(version uint64, oldRoot typedHash) error {
	prefix := v4WriteLogKeyFmt.Encode(version, &oldRoot)
	it := v5.readTxn.NewIterator(badger.IteratorOptions{Prefix: prefix})
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		if err := v5.changeBatch.DeleteAt(it.Item().KeyCopy(nil), it.Item().Version()); err != nil {
			return fmt.Errorf("error pruning writelog: %w", err)
		}
	}
	return nil
}

func (v5 *v5Migrator) TargetVersion() uint64 {
	return 5
}

func (v5 *v5Migrator) Migrate() (rversion uint64, rerr error) {
	v5.readTxn = v5.db.db.NewTransactionAt(maxTimestamp, false)
	defer func() {
		// readTxn will change throughout the process, don't
		// bind the defer to a particular instance.
		v5.readTxn.Discard()
	}()
	v5.changeBatch = v5.db.db.NewWriteBatchAt(maxTimestamp)
	defer func() {
		// changeBatch will change throughout the process, don't
		// bind the defer to a particular instance.
		v5.changeBatch.Cancel()
	}()

	// Load migration metadata.
	err := v5.meta.load(v5.db.db)
	if err != nil && err != badger.ErrKeyNotFound {
		return 0, err
	}
	v5.meta.BaseDBVersion = 4

	// Load metadata and update version.
	var meta4 v4SerializedMetadata
	item, err := v5.readTxn.Get(v4MetadataKeyFmt.Encode())
	if err != nil {
		return 0, fmt.Errorf("error reading database metadata: %w", err)
	}
	err = item.Value(func(data []byte) error {
		return cbor.UnmarshalTrusted(data, &meta4)
	})
	if err != nil {
		return 0, fmt.Errorf("error decoding database metadata: %w", err)
	}
	metaVersion := item.Version()

	meta5 := meta4
	meta5.Version = 5

	entry := badger.NewEntry(
		v5MetadataKeyFmt.Encode(),
		cbor.Marshal(meta5),
	)
	err = v5.changeBatch.SetEntryAt(entry, metaVersion)
	if err != nil {
		return 0, fmt.Errorf("error storing updated database metadata: %w", err)
	}

	// Determine last finalized version.
	var firstVersion uint64
	if v := meta5.LastFinalizedVersion; v != nil {
		firstVersion = *v
	}
	// Determine last applied version.
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	opts.Reverse = true
	it := v5.readTxn.NewIterator(opts)
	it.Rewind()
	it.Seek(v4RootsMetadataKeyFmt.Encode(uint64(math.MaxUint64)))
	var lastVersion uint64
	v4RootsMetadataKeyFmt.Decode(it.Item().Key(), &lastVersion)
	it.Close()

	migratedRoots := make(map[typedHash]v5MigratedRoot)
	if lv := v5.meta.LastMigratedVersion; lv != nil {
		// Resume at the following version.
		lastVersion = *lv - 1
	}
	if mr := v5.meta.LastMigratedRoots; mr != nil {
		migratedRoots = mr
	}
	for v := lastVersion; v >= firstVersion; v-- {
		var exists bool
		exists, err = v5.migrateVersion(v, migratedRoots)
		if err != nil {
			return 0, fmt.Errorf("error migrating version %d: %w", v, err)
		}
		if !exists {
			break
		}
	}

	// Make sure to prune any write logs which originate before the first version.
	for old, new := range migratedRoots {
		if new.Version != firstVersion {
			continue
		}
		if err = v5.pruneWriteLog(new.Version, old); err != nil {
			return 0, fmt.Errorf("error pruning old writelogs: %w", err)
		}
	}

	// Remove any data and metadata for versions less than firstVersion.
	v5.db.db.SetDiscardTs(versionToTs(firstVersion))

	if firstVersion > 0 {
		v5.helper.DisplayStepBegin("pruning old versions")

		pruneStartVersion := firstVersion - 1
		if lv := v5.meta.LastPrunedVersion; lv != nil {
			// Resume pruning at the following version.
			pruneStartVersion = *lv - 1
		}
		for v := pruneStartVersion; v != math.MaxUint64; v-- {
			if err = v5.pruneVersion(v); err != nil {
				return 0, fmt.Errorf("error pruning version %d: %w", v, err)
			}
		}

		v5.helper.DisplayStepEnd("done")
	}

	// Update earliest version.
	meta5.EarliestVersion = firstVersion
	entry = badger.NewEntry(
		v5MetadataKeyFmt.Encode(),
		cbor.Marshal(meta5),
	)
	err = v5.changeBatch.SetEntryAt(entry, metaVersion)
	if err != nil {
		return 0, fmt.Errorf("error storing updated database metadata: %w", err)
	}

	// All done, flush and clean up.
	v5.done = true
	if err = v5.flush(true); err != nil {
		return 0, err
	}
	return 5, nil
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

		helper.DisplayStep(fmt.Sprintf("migrating from v%d to v%d", lastVersion, migrator.TargetVersion()))

		newVersion, err := migrator.Migrate()
		if err != nil {
			return 0, fmt.Errorf("mkvs/badger/migrate: error while migrating from version %d: %w", lastVersion, err)
		}
		lastVersion = newVersion
	}

	return lastVersion, nil
}
