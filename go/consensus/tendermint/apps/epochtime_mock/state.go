package epochtimemock

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs"
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
	is *abciAPI.ImmutableState
}

func (s *immutableState) getEpoch(ctx context.Context) (api.EpochTime, int64, error) {
	data, err := s.is.Get(ctx, epochCurrentKeyFmt.Encode())
	if err != nil {
		return api.EpochInvalid, 0, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return api.EpochTime(0), 0, nil
	}

	var state mockEpochTimeState
	if err = cbor.Unmarshal(data, &state); err != nil {
		return api.EpochInvalid, 0, abciAPI.UnavailableStateError(err)
	}
	return state.Epoch, state.Height, nil
}

func (s *immutableState) getFutureEpoch(ctx context.Context) (*mockEpochTimeState, error) {
	data, err := s.is.Get(ctx, epochFutureKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var state mockEpochTimeState
	if err := cbor.Unmarshal(data, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &state, nil
}

func newImmutableState(ctx context.Context, state abciAPI.ApplicationState, version int64) (*immutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{is}, nil
}

type mutableState struct {
	*immutableState

	ms mkvs.KeyValueTree
}

func (s *mutableState) setEpoch(ctx context.Context, epoch api.EpochTime, height int64) error {
	state := mockEpochTimeState{Epoch: epoch, Height: height}
	err := s.ms.Insert(ctx, epochCurrentKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *mutableState) setFutureEpoch(ctx context.Context, epoch api.EpochTime, height int64) error {
	future, err := s.getFutureEpoch(ctx)
	if err != nil {
		return err
	}
	if future != nil {
		return fmt.Errorf("epochtime_mock: future epoch already pending")
	}

	state := mockEpochTimeState{Epoch: epoch, Height: height}
	err = s.ms.Insert(ctx, epochFutureKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *mutableState) clearFutureEpoch(ctx context.Context) error {
	err := s.ms.Remove(ctx, epochFutureKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}

func newMutableState(tree mkvs.KeyValueTree) *mutableState {
	return &mutableState{
		immutableState: &immutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
