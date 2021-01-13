package state

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// runtimeKeyFmt is the key format used for per-runtime roothash state.
	//
	// Value is CBOR-serialized roothash.RuntimeState.
	runtimeKeyFmt = keyformat.New(0x20, keyformat.H(&common.Namespace{}))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized roothash.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x21)
	// roundTimeoutQueueKeyFmt is the key format used for the round timeout queue.
	//
	// The format is (height, runtimeID). Value is runtimeID.
	roundTimeoutQueueKeyFmt = keyformat.New(0x22, int64(0), keyformat.H(&common.Namespace{}))
	// rejectTransactionsKeyFmt is the key format used to disable transactions.
	//
	// Value is a CBOR-serialized `true`.
	rejectTransactionsKeyFmt = keyformat.New(0x23)
	// evidenceKeyFmt is the key format used for storing valid misbehaviour evidence.
	//
	// Key format is: 0x24 <H(runtime-id) (hash.Hash)> <round (uint64)> <evidence-hash (hash.Hash)>
	evidenceKeyFmt = keyformat.New(0x24, keyformat.H(&common.Namespace{}), uint64(0), &hash.Hash{})

	cborTrue = cbor.Marshal(true)
)

// ImmutableState is the immutable roothash state wrapper.
type ImmutableState struct {
	is *api.ImmutableState
}

func NewImmutableState(ctx context.Context, state api.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := api.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

func (s *ImmutableState) runtimesWithRoundTimeouts(ctx context.Context, height *int64) ([]common.Namespace, []int64, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var startKey []byte
	if height == nil {
		startKey = roundTimeoutQueueKeyFmt.Encode()
	} else {
		startKey = roundTimeoutQueueKeyFmt.Encode(height)
	}

	var runtimeIDs []common.Namespace
	var heights []int64
	for it.Seek(startKey); it.Valid(); it.Next() {
		var decHeight int64
		if !roundTimeoutQueueKeyFmt.Decode(it.Key(), &decHeight) || (height != nil && decHeight != *height) {
			break
		}

		var runtimeID common.Namespace
		if err := runtimeID.UnmarshalBinary(it.Value()); err != nil {
			return nil, nil, api.UnavailableStateError(err)
		}

		runtimeIDs = append(runtimeIDs, runtimeID)
		if height == nil {
			heights = append(heights, decHeight)
		}
	}
	return runtimeIDs, heights, nil
}

// RuntimesWithRoundTimeouts returns the runtimes that have round timeouts scheduled at the given
// height.
func (s *ImmutableState) RuntimesWithRoundTimeouts(ctx context.Context, height int64) ([]common.Namespace, error) {
	runtimeIDs, _, err := s.runtimesWithRoundTimeouts(ctx, &height)
	return runtimeIDs, err
}

// RuntimesWithRoundTimeoutsAny returns the runtimes that have round timeouts scheduled at any
// height.
func (s *ImmutableState) RuntimesWithRoundTimeoutsAny(ctx context.Context) ([]common.Namespace, []int64, error) {
	return s.runtimesWithRoundTimeouts(ctx, nil)
}

// RuntimeState returns the roothash runtime state for a specific runtime.
func (s *ImmutableState) RuntimeState(ctx context.Context, id common.Namespace) (*roothash.RuntimeState, error) {
	raw, err := s.is.Get(ctx, runtimeKeyFmt.Encode(&id))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, roothash.ErrInvalidRuntime
	}

	var state roothash.RuntimeState
	if err = cbor.Unmarshal(raw, &state); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &state, nil
}

// Runtimes returns the list of all roothash runtime states.
func (s *ImmutableState) Runtimes(ctx context.Context) ([]*roothash.RuntimeState, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var runtimes []*roothash.RuntimeState
	for it.Seek(runtimeKeyFmt.Encode()); it.Valid(); it.Next() {
		if !runtimeKeyFmt.Decode(it.Key()) {
			break
		}

		var state roothash.RuntimeState
		if err := cbor.Unmarshal(it.Value(), &state); err != nil {
			return nil, api.UnavailableStateError(err)
		}

		runtimes = append(runtimes, &state)
	}
	if it.Err() != nil {
		return nil, api.UnavailableStateError(it.Err())
	}
	return runtimes, nil
}

// ConsensusParameters returns the roothash consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*roothash.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("tendermint/roothash: expected consensus parameters to be present in app state")
	}

	var params roothash.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &params, nil
}

// RejectTransactions returns true iff all transactions should be rejected.
func (s *ImmutableState) RejectTransactions(ctx context.Context) (bool, error) {
	raw, err := s.is.Get(ctx, rejectTransactionsKeyFmt.Encode())
	if err != nil {
		return false, api.UnavailableStateError(err)
	}
	if raw == nil {
		return false, nil
	}

	// This only ever will be true if present.
	return true, nil
}

// EvidenceHashExists returns true if the evidence hash for the runtime exists.
func (s *ImmutableState) EvidenceHashExists(ctx context.Context, runtimeID common.Namespace, round uint64, hash hash.Hash) (bool, error) {
	data, err := s.is.Get(ctx, evidenceKeyFmt.Encode(&runtimeID, round, &hash))
	return data != nil, api.UnavailableStateError(err)
}

// MutableState is the mutable roothash state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&api.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}

// SetRuntimeState sets a runtime's roothash state.
func (s *MutableState) SetRuntimeState(ctx context.Context, state *roothash.RuntimeState) error {
	err := s.ms.Insert(ctx, runtimeKeyFmt.Encode(&state.Runtime.ID), cbor.Marshal(state))
	return api.UnavailableStateError(err)
}

// SetConsensusParameters sets roothash consensus parameters.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *roothash.ConsensusParameters) error {
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return api.UnavailableStateError(err)
}

// ScheduleRoundTimeout schedules a new runtime round timeout at a given height.
func (s *MutableState) ScheduleRoundTimeout(ctx context.Context, runtimeID common.Namespace, height int64) error {
	encodedID, _ := runtimeID.MarshalBinary()
	err := s.ms.Insert(ctx, roundTimeoutQueueKeyFmt.Encode(height, &runtimeID), encodedID)
	return api.UnavailableStateError(err)
}

// ClearRoundTimeout clears a previously scheduled round timeout at a given height.
func (s *MutableState) ClearRoundTimeout(ctx context.Context, runtimeID common.Namespace, height int64) error {
	err := s.ms.Remove(ctx, roundTimeoutQueueKeyFmt.Encode(height, &runtimeID))
	return api.UnavailableStateError(err)
}

// SetRejectTransactions sets the transaction disable.
func (s *MutableState) SetRejectTransactions(ctx context.Context) error {
	err := s.ms.Insert(ctx, rejectTransactionsKeyFmt.Encode(), cborTrue)
	return api.UnavailableStateError(err)
}

// ClearRejectTransactions clears the transaction disable.
func (s *MutableState) ClearRejectTransactions(ctx context.Context) error {
	err := s.ms.Remove(ctx, rejectTransactionsKeyFmt.Encode())
	return api.UnavailableStateError(err)
}

// SetEvidenceHash sets the provided evidence hash.
func (s *MutableState) SetEvidenceHash(ctx context.Context, runtimeID common.Namespace, round uint64, hash hash.Hash) error {
	err := s.ms.Insert(ctx, evidenceKeyFmt.Encode(&runtimeID, round, &hash), []byte(""))
	return api.UnavailableStateError(err)
}

// RemoveExpiredEvidence removes expired evidence.
func (s *MutableState) RemoveExpiredEvidence(ctx context.Context, runtimeID common.Namespace, minRound uint64) error {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var toDelete [][]byte
	for it.Seek(evidenceKeyFmt.Encode(&runtimeID)); it.Valid(); it.Next() {
		var runtimeID keyformat.PreHashed
		var round uint64
		var hash hash.Hash
		if !evidenceKeyFmt.Decode(it.Key(), &runtimeID, &round, &hash) {
			break
		}
		if round > minRound {
			break
		}
		toDelete = append(toDelete, it.Key())
	}

	for _, key := range toDelete {
		if err := s.ms.Remove(ctx, key); err != nil {
			return api.UnavailableStateError(err)
		}
	}

	return nil
}
