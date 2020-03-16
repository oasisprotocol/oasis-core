package badger

import (
	"fmt"
	"sync"

	"github.com/dgraph-io/badger/v2"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
)

// serializedMetadata is the on-disk serialized metadata.
type serializedMetadata struct {
	// Version is the database schema version.
	Version uint64 `json:"version"`
	// Namespace is the namespace this database is for.
	Namespace common.Namespace `json:"namespace"`

	// EarliestRound is the earliest round.
	EarliestRound uint64 `json:"earliest_round"`
	// LastFinalizedRound is the last finalized round.
	LastFinalizedRound *uint64 `json:"last_finalized_round"`
}

// metadata is the database metadata.
type metadata struct {
	sync.RWMutex

	value serializedMetadata
}

func (m *metadata) getEarliestRound() uint64 {
	m.RLock()
	defer m.RUnlock()

	return m.value.EarliestRound
}

func (m *metadata) setEarliestRound(tx *badger.Txn, round uint64) error {
	m.Lock()
	defer m.Unlock()

	// The earliest round can only increase, not decrease.
	if round < m.value.EarliestRound {
		return nil
	}

	m.value.EarliestRound = round
	return m.save(tx)
}

func (m *metadata) getLastFinalizedRound() (uint64, bool) {
	m.RLock()
	defer m.RUnlock()

	if m.value.LastFinalizedRound == nil {
		return 0, false
	}
	return *m.value.LastFinalizedRound, true
}

func (m *metadata) setLastFinalizedRound(tx *badger.Txn, round uint64) error {
	m.Lock()
	defer m.Unlock()

	if m.value.LastFinalizedRound != nil && round <= *m.value.LastFinalizedRound {
		return nil
	}

	if m.value.LastFinalizedRound == nil {
		m.value.EarliestRound = round
	}

	m.value.LastFinalizedRound = &round
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

// rootsMetadata manages the roots metadata for a given round.
//
// NOTE: Public fields of this structure are part of the on-disk format.
type rootsMetadata struct {
	_ struct{} `cbor:",toarray"`

	// Roots is the map of a root created in a round to any derived roots (in this or later rounds).
	Roots map[hash.Hash][]hash.Hash

	// round is the round this metadata is for.
	round uint64
}

// loadRootsMetadata loads the roots metadata for the given round from the database.
func loadRootsMetadata(tx *badger.Txn, round uint64) (*rootsMetadata, error) {
	rootsMeta := &rootsMetadata{round: round}
	item, err := tx.Get(rootsMetadataKeyFmt.Encode(round))
	switch err {
	case nil:
		if err = item.Value(func(val []byte) error { return cbor.Unmarshal(val, &rootsMeta) }); err != nil {
			return nil, fmt.Errorf("mkvs/badger: error reading roots metadata: %w", err)
		}
	case badger.ErrKeyNotFound:
		rootsMeta.Roots = make(map[hash.Hash][]hash.Hash)
	default:
		return nil, fmt.Errorf("mkvs/badger: error reading roots metadata: %w", err)
	}
	return rootsMeta, nil
}

// save saves the roots metadata to the database.
func (rm *rootsMetadata) save(tx *badger.Txn) error {
	return tx.Set(rootsMetadataKeyFmt.Encode(rm.round), cbor.Marshal(rm))
}
