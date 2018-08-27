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
	// Per-contract state.
	stateContractMap = "roothash/%s"

	// Highest hex-encoded node/entity/contract identifier.
	// TODO: Should we move this to common?
	lastID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

var (
	_ cbor.Marshaler   = (*ContractState)(nil)
	_ cbor.Unmarshaler = (*ContractState)(nil)
)

// ContractState is the per-contract roothash state.
type ContractState struct {
	ID           signature.PublicKey `codec:"id"`
	CurrentBlock *api.Block          `codec:"current_block"`
	Round        *round              `codec:"round"`
	Timer        abci.Timer          `codec:"timer"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *ContractState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *ContractState) UnmarshalCBOR(data []byte) error {
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

// GetContractState returns contract state for given contract.
func (s *ImmutableState) GetContractState(id signature.PublicKey) (*ContractState, error) {
	_, raw := s.snapshot.Get([]byte(fmt.Sprintf(stateContractMap, id.String())))
	if raw == nil {
		return nil, nil
	}

	var state ContractState
	err := state.UnmarshalCBOR(raw)
	return &state, err
}

// GetContracts returns a list of all registered contract states.
func (s *ImmutableState) GetContracts() []*ContractState {
	var contracts []*ContractState
	s.snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateContractMap, "")),
		[]byte(fmt.Sprintf(stateContractMap, lastID)),
		true,
		func(key, value []byte, version int64) bool {
			var state ContractState
			cbor.MustUnmarshal(value, &state)

			contracts = append(contracts, &state)
			return false
		},
	)

	return contracts
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

// UpdateContractState updates roothash state for given contract.
func (s *MutableState) UpdateContractState(state *ContractState) {
	s.tree.Set(
		[]byte(fmt.Sprintf(stateContractMap, state.ID.String())),
		state.MarshalCBOR(),
	)
}
