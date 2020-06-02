package state

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// runtimeKeyFmt is the key format used for per-runtime roothash state.
	//
	// Value is CBOR-serialized runtime state.
	runtimeKeyFmt = keyformat.New(0x20, keyformat.H(&common.Namespace{}))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized roothash.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x21)
)

// RuntimeState is the per-runtime roothash state.
type RuntimeState struct {
	Runtime   *registry.Runtime `json:"runtime"`
	Suspended bool              `json:"suspended,omitempty"`

	CurrentBlock *block.Block `json:"current_block"`
	GenesisBlock *block.Block `json:"genesis_block"`

	Round *Round     `json:"round"`
	Timer abci.Timer `json:"timer"`
}

// ImmutableState is the immutable roothash state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// RuntimeState returns the roothash runtime state for a specific runtime.
func (s *ImmutableState) RuntimeState(ctx context.Context, id common.Namespace) (*RuntimeState, error) {
	raw, err := s.is.Get(ctx, runtimeKeyFmt.Encode(&id))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, roothash.ErrInvalidRuntime
	}

	var state RuntimeState
	if err = cbor.Unmarshal(raw, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &state, nil
}

// Runtimes returns the list of all roothash runtime states.
func (s *ImmutableState) Runtimes(ctx context.Context) ([]*RuntimeState, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var runtimes []*RuntimeState
	for it.Seek(runtimeKeyFmt.Encode()); it.Valid(); it.Next() {
		if !runtimeKeyFmt.Decode(it.Key()) {
			break
		}

		var state RuntimeState
		if err := cbor.Unmarshal(it.Value(), &state); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		runtimes = append(runtimes, &state)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return runtimes, nil
}

// ConsensusParameters returns the roothash consensus parameters.
func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*roothash.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("tendermint/roothash: expected consensus parameters to be present in app state")
	}

	var params roothash.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

// MutableState is the mutable roothash state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}

// SetRuntimeState sets a runtime's roothash state.
func (s *MutableState) SetRuntimeState(ctx context.Context, state *RuntimeState) error {
	err := s.ms.Insert(ctx, runtimeKeyFmt.Encode(&state.Runtime.ID), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

// SetConsensusParameters sets roothash consensus parameters.
func (s *MutableState) SetConsensusParameters(ctx context.Context, params *roothash.ConsensusParameters) error {
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}
