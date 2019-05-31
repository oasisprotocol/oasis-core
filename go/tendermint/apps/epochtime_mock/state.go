package epochtimemock

import (
	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	// Mock epochtime state.
	stateCurrentEpoch = "epochtime_mock/current"
	stateFutureEpoch  = "epochtime_mock/future"
)

var (
	_ cbor.Marshaler   = (*mockEpochTimeState)(nil)
	_ cbor.Unmarshaler = (*mockEpochTimeState)(nil)
)

type mockEpochTimeState struct {
	Epoch  api.EpochTime `codec:"epoch"`
	Height int64         `codec:"height"`
}

func (s *mockEpochTimeState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

func (s *mockEpochTimeState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getEpoch() (api.EpochTime, int64, error) {
	_, raw := s.Snapshot.Get([]byte(stateCurrentEpoch))
	if raw == nil {
		return api.EpochTime(0), 0, nil
	}

	var state mockEpochTimeState
	err := state.UnmarshalCBOR(raw)
	return state.Epoch, state.Height, err
}

func (s *immutableState) getFutureEpoch() (*mockEpochTimeState, error) {
	_, raw := s.Snapshot.Get([]byte(stateFutureEpoch))
	if raw == nil {
		return nil, nil
	}

	var state mockEpochTimeState
	if err := state.UnmarshalCBOR(raw); err != nil {
		return nil, errors.Wrap(err, "epochtime_mock: failed to unmarshal future epoch")
	}
	return &state, nil
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

type mutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *mutableState) setEpoch(epoch api.EpochTime, height int64) {
	state := mockEpochTimeState{Epoch: epoch, Height: height}

	s.tree.Set(
		[]byte(stateCurrentEpoch),
		state.MarshalCBOR(),
	)
}

func (s *mutableState) setFutureEpoch(epoch api.EpochTime, height int64) error {
	future, err := s.getFutureEpoch()
	if err != nil {
		return err
	}
	if future != nil {
		return errors.New("epochtime_mock: future epoch already pending")
	}

	state := mockEpochTimeState{Epoch: epoch, Height: height}

	s.tree.Set(
		[]byte(stateFutureEpoch),
		state.MarshalCBOR(),
	)

	return nil
}

func (s *mutableState) clearFutureEpoch() {
	s.tree.Remove([]byte(stateFutureEpoch))
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
