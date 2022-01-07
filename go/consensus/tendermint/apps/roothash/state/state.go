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
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
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
	// evidenceKeyFmt is the key format used for storing valid misbehaviour evidence.
	//
	// Key format is: 0x24 <H(runtime-id) (hash.Hash)> <round (uint64)> <evidence-hash (hash.Hash)>
	evidenceKeyFmt = keyformat.New(0x24, keyformat.H(&common.Namespace{}), uint64(0), &hash.Hash{})
	// stateRootKeyFmt is the key format used for runtime state roots.
	//
	// Value is the runtime's latest state root.
	stateRootKeyFmt = keyformat.New(0x25, keyformat.H(&common.Namespace{}))
	// ioRootKeyFmt is the key format used for runtime I/O roots.
	//
	// Value is the runtime's latest I/O root.
	ioRootKeyFmt = keyformat.New(0x26, keyformat.H(&common.Namespace{}))
	// lastRoundResultsKeyFmt is the key format used for last normal round results.
	//
	// Value is CBOR-serialized roothash.RoundResults.
	lastRoundResultsKeyFmt = keyformat.New(0x27, keyformat.H(&common.Namespace{}))
	// inMsgQueueMetaKeyFmt is the key format used for incoming message queue metadata.
	//
	// Value is CBOR-serialized message.IncomingMessageQueueMeta.
	inMsgQueueMetaKeyFmt = keyformat.New(0x28, keyformat.H(&common.Namespace{}))
	// inMsgQueueKeyFmt is the key format used for the incoming message queue.
	//
	// Value is CBOR-serialized message.IncomingMessage.
	inMsgQueueKeyFmt = keyformat.New(0x29, keyformat.H(&common.Namespace{}), uint64(0))
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

// LastRoundResults returns the last normal round results for a specific runtime.
func (s *ImmutableState) LastRoundResults(ctx context.Context, id common.Namespace) (*roothash.RoundResults, error) {
	raw, err := s.is.Get(ctx, lastRoundResultsKeyFmt.Encode(&id))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return &roothash.RoundResults{}, nil
	}

	var results roothash.RoundResults
	if err = cbor.Unmarshal(raw, &results); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &results, nil
}

func (s *ImmutableState) getRoot(ctx context.Context, id common.Namespace, kf *keyformat.KeyFormat) (hash.Hash, error) {
	raw, err := s.is.Get(ctx, kf.Encode(&id))
	if err != nil {
		return hash.Hash{}, api.UnavailableStateError(err)
	}
	if raw == nil {
		return hash.Hash{}, roothash.ErrInvalidRuntime
	}

	var h hash.Hash
	if err = h.UnmarshalBinary(raw); err != nil {
		return hash.Hash{}, api.UnavailableStateError(err)
	}
	return h, nil
}

// StateRoot returns the state root for a specific runtime.
func (s *ImmutableState) StateRoot(ctx context.Context, id common.Namespace) (hash.Hash, error) {
	return s.getRoot(ctx, id, stateRootKeyFmt)
}

// IORoot returns the state root for a specific runtime.
func (s *ImmutableState) IORoot(ctx context.Context, id common.Namespace) (hash.Hash, error) {
	return s.getRoot(ctx, id, ioRootKeyFmt)
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

// EvidenceHashExists returns true if the evidence hash for the runtime exists.
func (s *ImmutableState) EvidenceHashExists(ctx context.Context, runtimeID common.Namespace, round uint64, hash hash.Hash) (bool, error) {
	data, err := s.is.Get(ctx, evidenceKeyFmt.Encode(&runtimeID, round, &hash))
	return data != nil, api.UnavailableStateError(err)
}

// IncomingMessageQueueMeta returns the incoming message queue metadata for the given runtime.
func (s *ImmutableState) IncomingMessageQueueMeta(ctx context.Context, runtimeID common.Namespace) (*message.IncomingMessageQueueMeta, error) {
	raw, err := s.is.Get(ctx, inMsgQueueMetaKeyFmt.Encode(&runtimeID))
	if err != nil {
		return nil, api.UnavailableStateError(err)
	}
	if raw == nil {
		return &message.IncomingMessageQueueMeta{}, nil
	}

	var meta message.IncomingMessageQueueMeta
	if err = cbor.Unmarshal(raw, &meta); err != nil {
		return nil, api.UnavailableStateError(err)
	}
	return &meta, nil
}

// IncomingMessageQueue returns a list of queued messages, starting with the passed offset.
func (s *ImmutableState) IncomingMessageQueue(ctx context.Context, runtimeID common.Namespace, offset uint64, limit uint32) ([]*message.IncomingMessage, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var msgs []*message.IncomingMessage
	for it.Seek(inMsgQueueKeyFmt.Encode(&runtimeID, offset)); it.Valid(); it.Next() {
		var (
			decRuntimeID keyformat.PreHashed
			decID        uint64
		)
		if !inMsgQueueKeyFmt.Decode(it.Key(), &decRuntimeID, &decID) {
			break
		}
		if decID < offset {
			continue
		}

		var msg message.IncomingMessage
		if err := cbor.Unmarshal(it.Value(), &msg); err != nil {
			return nil, api.UnavailableStateError(err)
		}

		msgs = append(msgs, &msg)
		if limit > 0 && uint32(len(msgs)) >= limit {
			break
		}
	}
	if it.Err() != nil {
		return nil, api.UnavailableStateError(it.Err())
	}
	return msgs, nil
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
	if err := s.ms.Insert(ctx, runtimeKeyFmt.Encode(&state.Runtime.ID), cbor.Marshal(state)); err != nil {
		return api.UnavailableStateError(err)
	}

	// Store the current state and I/O roots separately to make them easier to retrieve when
	// constructing proofs of runtime state.
	stateRoot, _ := state.CurrentBlock.Header.StateRoot.MarshalBinary()
	ioRoot, _ := state.CurrentBlock.Header.IORoot.MarshalBinary()

	if err := s.ms.Insert(ctx, stateRootKeyFmt.Encode(&state.Runtime.ID), stateRoot); err != nil {
		return api.UnavailableStateError(err)
	}
	if err := s.ms.Insert(ctx, ioRootKeyFmt.Encode(&state.Runtime.ID), ioRoot); err != nil {
		return api.UnavailableStateError(err)
	}
	return nil
}

// SetLastRoundResults sets a runtime's last normal round results.
func (s *MutableState) SetLastRoundResults(ctx context.Context, runtimeID common.Namespace, results *roothash.RoundResults) error {
	err := s.ms.Insert(ctx, lastRoundResultsKeyFmt.Encode(&runtimeID), cbor.Marshal(results))
	return api.UnavailableStateError(err)
}

// SetConsensusParameters sets roothash consensus parameters.
//
// NOTE: This method must only be called from InitChain/EndBlock contexts.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *roothash.ConsensusParameters) error {
	if err := s.is.CheckContextMode(ctx, []api.ContextMode{api.ContextInitChain, api.ContextEndBlock}); err != nil {
		return err
	}
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

// SetIncomingMessageQueueMeta sets the incoming message queue metadata.
func (s *MutableState) SetIncomingMessageQueueMeta(ctx context.Context, runtimeID common.Namespace, meta *message.IncomingMessageQueueMeta) error {
	err := s.ms.Insert(ctx, inMsgQueueMetaKeyFmt.Encode(&runtimeID), cbor.Marshal(meta))
	return api.UnavailableStateError(err)
}

// SetIncomingMessageQueue sets an entry in the incoming message queue.
func (s *MutableState) SetIncomingMessageInQueue(ctx context.Context, runtimeID common.Namespace, msg *message.IncomingMessage) error {
	err := s.ms.Insert(ctx, inMsgQueueKeyFmt.Encode(&runtimeID, msg.ID), cbor.Marshal(msg))
	return api.UnavailableStateError(err)
}

// RemoveIncomingMessageFromQueue removes an entry from the incoming message queue.
func (s *MutableState) RemoveIncomingMessageFromQueue(ctx context.Context, runtimeID common.Namespace, id uint64) error {
	err := s.ms.Remove(ctx, inMsgQueueKeyFmt.Encode(&runtimeID, id))
	return api.UnavailableStateError(err)
}
