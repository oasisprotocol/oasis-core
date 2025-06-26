package pathbadger

import (
	"fmt"
	"math"
	"sync"

	"github.com/dgraph-io/badger/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
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
	// MultipartVersion is the version for the in-progress multipart restore, or 0 if none was in
	// progress.
	MultipartVersion uint64 `json:"multipart_version,omitempty"`
	// MultipartSeqs are the sequence numbers used for the multipart restore.
	MultipartSeqs map[uint8]uint16 `json:"multipart_seqs,omitempty"`

	// NextPendingRootSeq contains the next pending root sequence number for a given type in the
	// given version.
	NextPendingRootSeq map[uint64]map[uint8]uint16 `json:"next_pending_root_seq,omitempty"`
	// PendingRootSeqs contains the set of all non-finalized roots in the next version.
	PendingRootSeqs map[uint64]map[api.TypedHash]uint16 `json:"pending_root_seqs,omitempty"`
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

func (m *metadata) setEarliestVersion(version uint64) {
	m.Lock()
	defer m.Unlock()

	// The earliest version can only increase, not decrease.
	if version < m.value.EarliestVersion {
		panic(fmt.Errorf("mkvs/pathbadger: earliest version must only increase"))
	}

	m.value.EarliestVersion = version
}

func (m *metadata) getLastFinalizedVersion() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.value.LastFinalizedVersion == nil {
		return 0, false
	}
	return *m.value.LastFinalizedVersion, true
}

func (m *metadata) setLastFinalizedVersion(version uint64) {
	m.Lock()
	defer m.Unlock()

	if m.value.LastFinalizedVersion != nil && version <= *m.value.LastFinalizedVersion {
		// Note that we cannot use a more strict check here because forward jumps are allowed in
		// case of multipart restore.
		return
	}

	if m.value.LastFinalizedVersion == nil {
		m.value.EarliestVersion = version
	}

	m.value.LastFinalizedVersion = &version
	delete(m.value.NextPendingRootSeq, version)
	delete(m.value.PendingRootSeqs, version)
}

func (m *metadata) getMultipart() (uint64, map[uint8]uint16) {
	m.RLock()
	defer m.RUnlock()

	return m.value.MultipartVersion, m.value.MultipartSeqs
}

func (m *metadata) setMultipart(version uint64, meta map[uint8]*multipartMeta) {
	m.Lock()
	defer m.Unlock()

	m.value.MultipartVersion = version

	switch meta {
	case nil:
		m.value.MultipartSeqs = nil
	default:
		m.value.MultipartSeqs = make(map[uint8]uint16)
		for t, md := range meta {
			m.value.MultipartSeqs[t] = md.seqNo
		}
	}
}

func (m *metadata) reserveRootSeqNo(version uint64, rootType uint8) (uint16, error) {
	m.Lock()
	defer m.Unlock()

	if len(m.value.NextPendingRootSeq) > api.MaxPendingVersions {
		return math.MaxUint16, fmt.Errorf("mkvs/pathbadger: too many non-finalized versions")
	}

	if m.value.NextPendingRootSeq == nil {
		m.value.NextPendingRootSeq = make(map[uint64]map[uint8]uint16)
	}
	if m.value.NextPendingRootSeq[version] == nil {
		m.value.NextPendingRootSeq[version] = make(map[uint8]uint16)
	}
	seqNo := m.value.NextPendingRootSeq[version][rootType]
	if seqNo == math.MaxUint16 {
		return math.MaxUint16, fmt.Errorf("mkvs/pathbadger: too many non-finalized roots in version %d", version)
	}
	m.value.NextPendingRootSeq[version][rootType]++

	return seqNo, nil
}

func (m *metadata) setPendingRootSeqNo(version uint64, rootHash api.TypedHash, seqNo uint16) error {
	m.Lock()
	defer m.Unlock()

	if len(m.value.PendingRootSeqs) > api.MaxPendingVersions {
		return fmt.Errorf("mkvs/pathbadger: too many non-finalized versions")
	}

	if m.value.PendingRootSeqs == nil {
		m.value.PendingRootSeqs = make(map[uint64]map[api.TypedHash]uint16)
	}
	if m.value.PendingRootSeqs[version] == nil {
		m.value.PendingRootSeqs[version] = make(map[api.TypedHash]uint16)
	}
	m.value.PendingRootSeqs[version][rootHash] = seqNo

	return nil
}

func (m *metadata) getPendingRootSeqNo(version uint64, rootHash api.TypedHash) (uint16, bool) {
	m.Lock()
	defer m.Unlock()

	seqNo, ok := m.value.PendingRootSeqs[version][rootHash]
	return seqNo, ok
}

func (m *metadata) commit(tx *badger.Txn) {
	// The only safe thing to do in case we cannot save metadata is to panic.
	err := tx.Set(metadataKeyFmt.Encode(), cbor.Marshal(m.value))
	if err != nil {
		panic(fmt.Errorf("mkvs/pathbadger: failed to save metadata: %w", err))
	}

	err = tx.CommitAt(tsMetadata, nil)
	if err != nil {
		panic(fmt.Errorf("mkvs/pathbadger: failed to commit metadata: %w", err))
	}
}

// updatedNode is an element of the root updated nodes key.
//
// NOTE: Public fields of this structure are part of the on-disk format.
type updatedNode struct {
	_ struct{} `cbor:",toarray"` // nolint

	Removed bool
	Key     []byte
}
