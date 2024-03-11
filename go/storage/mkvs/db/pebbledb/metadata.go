package pebbledb

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"

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

func (m *metadata) setEarliestVersion(batch *pebble.Batch, version uint64) {
	m.Lock()
	defer m.Unlock()

	// The earliest version can only increase, not decrease.
	if version < m.value.EarliestVersion {
		return
	}

	m.value.EarliestVersion = version
	_ = m.save(batch, nil)
}

func (m *metadata) getLastFinalizedVersion() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.value.LastFinalizedVersion == nil {
		return 0, false
	}
	return *m.value.LastFinalizedVersion, true
}

func (m *metadata) setLastFinalizedVersion(batch *pebble.Batch, version uint64) error {
	m.Lock()
	defer m.Unlock()

	if m.value.LastFinalizedVersion != nil && version <= *m.value.LastFinalizedVersion {
		return nil
	}

	if m.value.LastFinalizedVersion == nil {
		m.value.EarliestVersion = version
	}

	m.value.LastFinalizedVersion = &version
	return batch.Set(metadataKeyFmt.Encode(), cbor.Marshal(m.value), nil)
}

func (m *metadata) getMultipartVersion() uint64 {
	m.Lock()
	defer m.Unlock()

	return m.value.MultipartVersion
}

func (m *metadata) setMultipartVersion(db *pebble.DB, version uint64, wo *pebble.WriteOptions) error {
	m.Lock()
	defer m.Unlock()

	m.value.MultipartVersion = version
	return m.save(db, wo)
}

func (m *metadata) save(db pebble.Writer, opts *pebble.WriteOptions) error {
	return db.Set(metadataKeyFmt.Encode(), cbor.Marshal(m.value), opts)
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
func loadRootsMetadata(db *pebble.DB, version uint64) (*rootsMetadata, error) {
	rootsMeta := &rootsMetadata{
		version: version,
	}

	item, closer, err := db.Get(rootsMetadataKeyFmt.Encode(version))
	switch {
	case err == nil:
		defer closer.Close()
		if err = cbor.Unmarshal(item, &rootsMeta); err != nil {
			return nil, fmt.Errorf("mkvs/pebbledb: failed to unmarshal roots metadata: %w", err)
		}
	case errors.Is(err, pebble.ErrNotFound):
		rootsMeta.Roots = make(map[node.TypedHash][]node.TypedHash)
	default:
		return nil, fmt.Errorf("mkvs/pebbledb: failed to get roots metadata from backing store: %w", err)
	}

	return rootsMeta, nil
}

// save saves the roots metadata to the database.
func (rm *rootsMetadata) save(batch *pebble.Batch) error {
	return batch.Set(rootsMetadataKeyFmt.Encode(rm.version), cbor.Marshal(rm), nil)
}
