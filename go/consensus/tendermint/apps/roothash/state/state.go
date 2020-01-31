package state

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

var (
	// runtimeKeyFmt is the key format used for per-runtime roothash state.
	//
	// Value is CBOR-serialized runtime state.
	runtimeKeyFmt = keyformat.New(0x20, &common.Namespace{})
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

type ImmutableState struct {
	*abci.ImmutableState
}

func NewImmutableState(state abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

func (s *ImmutableState) RuntimeState(id common.Namespace) (*RuntimeState, error) {
	_, raw := s.Snapshot.Get(runtimeKeyFmt.Encode(&id))
	if raw == nil {
		return nil, roothash.ErrInvalidRuntime
	}

	var state RuntimeState
	err := cbor.Unmarshal(raw, &state)
	return &state, err
}

func (s *ImmutableState) Runtimes() []*RuntimeState {
	var runtimes []*RuntimeState
	s.Snapshot.IterateRange(
		runtimeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !runtimeKeyFmt.Decode(key) {
				return true
			}

			var state RuntimeState
			cbor.MustUnmarshal(value, &state)

			runtimes = append(runtimes, &state)
			return false
		},
	)

	return runtimes
}

func (s *ImmutableState) ConsensusParameters() (*roothash.ConsensusParameters, error) {
	_, raw := s.Snapshot.Get(parametersKeyFmt.Encode())
	if raw == nil {
		return nil, fmt.Errorf("tendermint/roothash: expected consensus parameters to be present in app state")
	}

	var params roothash.ConsensusParameters
	err := cbor.Unmarshal(raw, &params)
	return &params, err
}

type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}

func (s *MutableState) SetRuntimeState(state *RuntimeState) {
	s.tree.Set(runtimeKeyFmt.Encode(&state.Runtime.ID), cbor.Marshal(state))
}

func (s *MutableState) SetConsensusParameters(params *roothash.ConsensusParameters) {
	s.tree.Set(parametersKeyFmt.Encode(), cbor.Marshal(params))
}
