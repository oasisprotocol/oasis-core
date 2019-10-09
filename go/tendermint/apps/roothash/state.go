package roothash

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/keyformat"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	// runtimeKeyFmt is the key format used for per-runtime roothash state.
	//
	// Value is CBOR-serialized runtime state.
	runtimeKeyFmt = keyformat.New(0x20, &signature.MapKey{})

	_ cbor.Marshaler   = (*runtimeState)(nil)
	_ cbor.Unmarshaler = (*runtimeState)(nil)
)

type runtimeState struct {
	Runtime      *registry.Runtime `json:"runtime"`
	CurrentBlock *block.Block      `json:"current_block"`
	GenesisBlock *block.Block      `json:"genesis_block"`
	Round        *round            `json:"round"`
	Timer        abci.Timer        `json:"timer"`
}

func (s *runtimeState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

func (s *runtimeState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

type immutableState struct {
	*abci.ImmutableState
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

func (s *immutableState) getRuntimeState(id signature.PublicKey) (*runtimeState, error) {
	_, raw := s.Snapshot.Get(runtimeKeyFmt.Encode(&id))
	if raw == nil {
		return nil, nil
	}

	var state runtimeState
	err := state.UnmarshalCBOR(raw)
	return &state, err
}

func (s *immutableState) getRuntimes() []*runtimeState {
	var runtimes []*runtimeState
	s.Snapshot.IterateRange(
		runtimeKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			if !runtimeKeyFmt.Decode(key) {
				return true
			}

			var state runtimeState
			cbor.MustUnmarshal(value, &state)

			runtimes = append(runtimes, &state)
			return false
		},
	)

	return runtimes
}

type mutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}

func (s *mutableState) updateRuntimeState(state *runtimeState) {
	s.tree.Set(runtimeKeyFmt.Encode(&state.Runtime.ID), state.MarshalCBOR())
}
