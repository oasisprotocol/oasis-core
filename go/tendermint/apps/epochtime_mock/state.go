package epochtimemock

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	// Mock epochtime state.
	stateCurrentEpoch = "epochtime_mock/current"
)

var (
	_ cbor.Marshaler   = (*MockEpochTimeState)(nil)
	_ cbor.Unmarshaler = (*MockEpochTimeState)(nil)
)

// MockEpochTimeState is the mock epochtime state.
type MockEpochTimeState struct {
	Epoch  api.EpochTime `codec:"epoch"`
	Height int64         `codec:"height"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *MockEpochTimeState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *MockEpochTimeState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

// ImmutableState is an immutable mock epochtime state wrapper.
type ImmutableState struct {
	snapshot *iavl.ImmutableTree
}

// NewImmutableState creates a new immutable mock epochtime state wrapper.
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

// GetEpoch returns the current epoch.
func (s *ImmutableState) GetEpoch() (api.EpochTime, int64, error) {
	_, raw := s.snapshot.Get([]byte(stateCurrentEpoch))
	if raw == nil {
		return api.EpochTime(0), 0, nil
	}

	var state MockEpochTimeState
	err := state.UnmarshalCBOR(raw)
	return state.Epoch, state.Height, err
}

// MutableState is a mutable mock epochtime state wrapper.
type MutableState struct {
	ImmutableState

	tree *iavl.MutableTree
}

// NewMutableState creates a new mutable mock epochtime state wrapper.
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

// SetEpoch sets the current epoch.
func (s *MutableState) SetEpoch(epoch api.EpochTime, height int64) {
	state := MockEpochTimeState{Epoch: epoch, Height: height}

	s.tree.Set(
		[]byte(stateCurrentEpoch),
		state.MarshalCBOR(),
	)
}
