package roothash

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

// Per-runtime state.
const stateRuntimeMap = "roothash/%s"

var (
	_ cbor.Marshaler   = (*runtimeState)(nil)
	_ cbor.Unmarshaler = (*runtimeState)(nil)
)

type runtimeState struct {
	Runtime      *registry.Runtime `codec:"runtime"`
	CurrentBlock *block.Block      `codec:"current_block"`
	Round        *round            `codec:"round"`
	Timer        abci.Timer        `codec:"timer"`
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
	_, raw := s.Snapshot.Get([]byte(fmt.Sprintf(stateRuntimeMap, id.String())))
	if raw == nil {
		return nil, nil
	}

	var state runtimeState
	err := state.UnmarshalCBOR(raw)
	return &state, err
}

func (s *immutableState) getRuntimes() []*runtimeState {
	var runtimes []*runtimeState
	s.Snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateRuntimeMap, abci.FirstID)),
		[]byte(fmt.Sprintf(stateRuntimeMap, abci.LastID)),
		true,
		func(key, value []byte, version int64) bool {
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
	s.tree.Set(
		[]byte(fmt.Sprintf(stateRuntimeMap, state.Runtime.ID.String())),
		state.MarshalCBOR(),
	)
}
