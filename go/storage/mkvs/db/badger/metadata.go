package badger

import (
	"fmt"
	"sync"

	"github.com/dgraph-io/badger/v3"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// serializedMetadata is the on-disk serialized metadata.
type serializedMetadata struct {
	// Version is the database schema version.
	Version uint64 `json:"version"`
	// Namespace is the namespace this database is for.
	Namespace common.Namespace `json:"namespace"`

	// EarliestVersion is the earliest version.
	EarliestVersion uint64 `json:"earliest_version"`
	// LastFinalizedVersion is the last finalized version.
	LastFinalizedVersion *uint64 `json:"last_finalized_version"`
	// MultipartVersion is the version for the in-progress multipart restore, or 0 if none was in progress.
	MultipartVersion uint64 `json:"multipart_version"`
}

// metadata is the database metadata.
type metadata struct {
	sync.RWMutex

	value serializedMetadata
}

func (m *metadata) getEarliestVersion() uint64 {
	m.RLock()
	defer m.RUnlock()

	return m.value.EarliestVersion
}

func (m *metadata) setEarliestVersion(tx *badger.Txn, version uint64) error {
	m.Lock()
	defer m.Unlock()

	// The earliest version can only increase, not decrease.
	if version < m.value.EarliestVersion {
		return nil
	}

	m.value.EarliestVersion = version
	return m.save(tx)
}

func (m *metadata) getLastFinalizedVersion() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.value.LastFinalizedVersion == nil {
		return 0, false
	}
	return *m.value.LastFinalizedVersion, true
}

func (m *metadata) setLastFinalizedVersion(tx *badger.Txn, version uint64) error {
	m.Lock()
	defer m.Unlock()

	if m.value.LastFinalizedVersion != nil && version <= *m.value.LastFinalizedVersion {
		return nil
	}

	if m.value.LastFinalizedVersion == nil {
		m.value.EarliestVersion = version
	}

	m.value.LastFinalizedVersion = &version
	return m.save(tx)
}

func (m *metadata) getMultipartVersion() uint64 {
	m.Lock()
	defer m.Unlock()

	return m.value.MultipartVersion
}

func (m *metadata) setMultipartVersion(tx *badger.Txn, version uint64) error {
	m.Lock()
	defer m.Unlock()

	m.value.MultipartVersion = version
	return m.save(tx)
}

func (m *metadata) save(tx *badger.Txn) error {
	return tx.Set(metadataKeyFmt.Encode(), cbor.Marshal(m.value))
}

// updatedNode is an element of the root updated nodes key.
//
// NOTE: Public fields of this structure are part of the on-disk format.
type updatedNode struct {
	_ struct{} `cbor:",toarray"` // nolint

	Removed bool
	Hash    hash.Hash
}

// rootsMetadata manages the roots metadata for a given version.
//
// NOTE: Public fields of this structure are part of the on-disk format.
type rootsMetadata struct {
	_ struct{} `cbor:",toarray"`

	// Roots is the map of a root created in a version to any derived roots (in this or later versions).
	Roots map[typedHash][]typedHash

	// version is the version this metadata is for.
	version uint64
}

// loadRootsMetadata loads the roots metadata for the given version from the database.
func loadRootsMetadata(tx *badger.Txn, version uint64) (*rootsMetadata, error) {
	rootsMeta := &rootsMetadata{version: version}
	item, err := tx.Get(rootsMetadataKeyFmt.Encode(version))
	switch err {
	case nil:
		if err = item.Value(func(val []byte) error { return cbor.Unmarshal(val, &rootsMeta) }); err != nil {
			return nil, fmt.Errorf("mkvs/badger: error reading roots metadata: %w", err)
		}
	case badger.ErrKeyNotFound:
		rootsMeta.Roots = make(map[typedHash][]typedHash)
	default:
		return nil, fmt.Errorf("mkvs/badger: error reading roots metadata: %w", err)
	}
	return rootsMeta, nil
}

// save saves the roots metadata to the database.
func (rm *rootsMetadata) save(tx *badger.Txn) error {
	return tx.Set(rootsMetadataKeyFmt.Encode(rm.version), cbor.Marshal(rm))
}
