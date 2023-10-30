package rocksdb

import (
	"fmt"
	"sync"

	"github.com/linxGnu/grocksdb"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
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

func (m *metadata) setEarliestVersion(batch *grocksdb.WriteBatch, version uint64) {
	m.Lock()
	defer m.Unlock()

	// The earliest version can only increase, not decrease.
	if version < m.value.EarliestVersion {
		return
	}

	m.value.EarliestVersion = version
	m.saveB(batch)
}

func (m *metadata) getLastFinalizedVersion() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.value.LastFinalizedVersion == nil {
		return 0, false
	}
	return *m.value.LastFinalizedVersion, true
}

func (m *metadata) setLastFinalizedVersion(batch *grocksdb.WriteBatch, version uint64) {
	m.Lock()
	defer m.Unlock()

	if m.value.LastFinalizedVersion != nil && version <= *m.value.LastFinalizedVersion {
		return
	}

	if m.value.LastFinalizedVersion == nil {
		m.value.EarliestVersion = version
	}

	m.value.LastFinalizedVersion = &version
	m.saveB(batch)
}

func (m *metadata) getMultipartVersion() uint64 {
	m.Lock()
	defer m.Unlock()

	return m.value.MultipartVersion
}

func (m *metadata) setMultipartVersion(db *grocksdb.DB, version uint64) error {
	m.Lock()
	defer m.Unlock()

	m.value.MultipartVersion = version
	return m.save(db)
}

func (m *metadata) save(db *grocksdb.DB) error {
	return db.Put(defaultWriteOptions, metadataKeyFmt.Encode(), cbor.Marshal(m.value))
}

// TODO: Collaps with save.
func (m *metadata) saveB(batch *grocksdb.WriteBatch) {
	batch.Put(metadataKeyFmt.Encode(), cbor.Marshal(m.value))
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
	Roots map[node.TypedHash][]node.TypedHash

	// version is the version this metadata is for.
	version uint64
}

// loadRootsMetadata loads the roots metadata for the given version from the database.
func loadRootsMetadata(db *grocksdb.DB, version uint64) (*rootsMetadata, error) {
	rootsMeta := &rootsMetadata{version: version}

	s, err := db.Get(defaultReadOptions, rootsMetadataKeyFmt.Encode(version))
	if err != nil {
		return nil, fmt.Errorf("mkvs/rocksdb: failed to get roots metadata from backing store: %w", err)
	}
	defer s.Free()
	switch s.Exists() {
	case false:
		rootsMeta.Roots = make(map[node.TypedHash][]node.TypedHash)
	case true:
		if err = cbor.Unmarshal(s.Data(), &rootsMeta); err != nil {
			return nil, fmt.Errorf("mkvs/rocksdb: failed to unmarshal roots metadata: %w", err)
		}
	}
	return rootsMeta, nil
}

// save saves the roots metadata to the database.
func (rm *rootsMetadata) save(batch *grocksdb.WriteBatch) {
	batch.Put(rootsMetadataKeyFmt.Encode(rm.version), cbor.Marshal(rm))
}
