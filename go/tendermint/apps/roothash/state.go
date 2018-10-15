package roothash

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	// Per-runtime state.
	stateRuntimeMap = "roothash/%s"

	// Highest hex-encoded node/entity/runtime identifier.
	// TODO: Should we move this to common?
	lastID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

var (
	_ cbor.Marshaler   = (*RuntimeState)(nil)
	_ cbor.Unmarshaler = (*RuntimeState)(nil)
)

// RuntimeState is the per-runtime roothash state.
type RuntimeState struct {
	ID           signature.PublicKey `codec:"id"`
	CurrentBlock *api.Block          `codec:"current_block"`
	Round        *round              `codec:"round"`
	Timer        abci.Timer          `codec:"timer"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *RuntimeState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *RuntimeState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

// ImmutableState is an immutable roothash state wrapper.
type ImmutableState struct {
	snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable roothash state wrapper.
func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	snapshot, err := state.DeliverTxTree().GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{snapshot: snapshot}, nil
}

// GetRuntimeState returns runtime state for given runtime.
func (s *ImmutableState) GetRuntimeState(id signature.PublicKey) (*RuntimeState, error) {
	_, raw := s.snapshot.Get([]byte(fmt.Sprintf(stateRuntimeMap, id.String())))
	if raw == nil {
		return nil, nil
	}

	var state RuntimeState
	err := state.UnmarshalCBOR(raw)
	return &state, err
}

// GetRuntimes returns a list of all registered runtime states.
func (s *ImmutableState) GetRuntimes() []*RuntimeState {
	var runtimes []*RuntimeState
	s.snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateRuntimeMap, "")),
		[]byte(fmt.Sprintf(stateRuntimeMap, lastID)),
		true,
		func(key, value []byte, version int64) bool {
			var state RuntimeState
			cbor.MustUnmarshal(value, &state)

			runtimes = append(runtimes, &state)
			return false
		},
	)

	return runtimes
}

// MutableState is a mutable roothash state wrapper.
type MutableState struct {
	ImmutableState

	tree *iavl.MutableTree
}

// NewMutableState creates a new mutable roothash state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	return &MutableState{
		ImmutableState: ImmutableState{snapshot: tree.ImmutableTree},
		tree:           tree,
	}
}

// Tree returns the backing mutable tree.
func (s *MutableState) Tree() *iavl.MutableTree {
	return s.tree
}

// UpdateRuntimeState updates roothash state for given runtime.
func (s *MutableState) UpdateRuntimeState(state *RuntimeState) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateRuntimeMap, state.ID.String())),
		state.MarshalCBOR(),
	)
}
