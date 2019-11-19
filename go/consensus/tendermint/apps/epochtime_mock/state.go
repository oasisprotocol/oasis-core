package epochtimemock

import (
	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
)

var (
	// epochCurrentKeyFmt is the current epoch key format.
	//
	// Value is CBOR-serialized mock epoch time state.
	epochCurrentKeyFmt = keyformat.New(0x30)
	// epochFutureKeyFmt is the future epoch key format.
	//
	// Value is CBOR-serialized mock epoch time state.
	epochFutureKeyFmt = keyformat.New(0x31)
)

type mockEpochTimeState struct {
	Epoch  api.EpochTime `json:"epoch"`
	Height int64         `json:"height"`
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getEpoch() (api.EpochTime, int64, error) {
	_, raw := s.Snapshot.Get(epochCurrentKeyFmt.Encode())
	if raw == nil {
		return api.EpochTime(0), 0, nil
	}

	var state mockEpochTimeState
	err := cbor.Unmarshal(raw, &state)
	return state.Epoch, state.Height, err
}

func (s *immutableState) getFutureEpoch() (*mockEpochTimeState, error) {
	_, raw := s.Snapshot.Get(epochFutureKeyFmt.Encode())
	if raw == nil {
		return nil, nil
	}

	var state mockEpochTimeState
	if err := cbor.Unmarshal(raw, &state); err != nil {
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
	s.tree.Set(epochCurrentKeyFmt.Encode(), cbor.Marshal(state))
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
	s.tree.Set(epochFutureKeyFmt.Encode(), cbor.Marshal(state))

	return nil
}

func (s *mutableState) clearFutureEpoch() {
	s.tree.Remove(epochFutureKeyFmt.Encode())
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
