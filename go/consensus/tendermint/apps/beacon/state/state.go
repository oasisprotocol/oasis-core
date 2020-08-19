package state

import (
	"context"
	"errors"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// epochCurrentKeyFmt is the current epoch key format.
	//
	// Value is CBOR-serialized epoch time state.
	epochCurrentKeyFmt = keyformat.New(0x40)
	// epochFutureKeyFmt is the future epoch key format.
	//
	// Value is CBOR-serialized epoch time state.
	epochFutureKeyFmt = keyformat.New(0x41)

	// beaconKeyFmt is the random beacon key format.
	//
	// Value is raw random beacon.
	beaconKeyFmt = keyformat.New(0x42)
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized beacon.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x43)
)

// EpochTimeState is the epoch state.
type EpochTimeState struct {
	Epoch  beacon.EpochTime `json:"epoch"`
	Height int64            `json:"height"`
}

// ImmutableState is the immutable beacon state wrapper.
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

// Beacon gets the current random beacon value.
func (s *ImmutableState) Beacon(ctx context.Context) ([]byte, error) {
	data, err := s.is.Get(ctx, beaconKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, beacon.ErrBeaconNotAvailable
	}
	return data, nil
}

func (s *ImmutableState) GetEpoch(ctx context.Context) (beacon.EpochTime, int64, error) {
	data, err := s.is.Get(ctx, epochCurrentKeyFmt.Encode())
	if err != nil {
		return beacon.EpochInvalid, 0, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return beacon.EpochTime(0), 0, nil
	}

	var state EpochTimeState
	if err = cbor.Unmarshal(data, &state); err != nil {
		return beacon.EpochInvalid, 0, abciAPI.UnavailableStateError(err)
	}
	return state.Epoch, state.Height, nil
}

func (s *ImmutableState) GetFutureEpoch(ctx context.Context) (*EpochTimeState, error) {
	data, err := s.is.Get(ctx, epochFutureKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var state EpochTimeState
	if err := cbor.Unmarshal(data, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &state, nil
}

func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*beacon.ConsensusParameters, error) {
	data, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, errors.New("tendermint/beacon: expected consensus parameters to be present in app state")
	}

	var params beacon.ConsensusParameters
	if err = cbor.Unmarshal(data, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

// MutableState is a mutable beacon state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

func (s *MutableState) SetBeacon(ctx context.Context, newBeacon []byte) error {
	if l := len(newBeacon); l != beacon.BeaconSize {
		return fmt.Errorf("tendermint/beacon: unexpected beacon size: %d", l)
	}

	err := s.ms.Insert(ctx, beaconKeyFmt.Encode(), newBeacon)
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetEpoch(ctx context.Context, epoch beacon.EpochTime, height int64) error {
	state := EpochTimeState{Epoch: epoch, Height: height}
	err := s.ms.Insert(ctx, epochCurrentKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetFutureEpoch(ctx context.Context, epoch beacon.EpochTime, height int64) error {
	future, err := s.GetFutureEpoch(ctx)
	if err != nil {
		return err
	}
	if future != nil {
		return fmt.Errorf("tendermint/beacon: future epoch already pending")
	}

	state := EpochTimeState{Epoch: epoch, Height: height}
	err = s.ms.Insert(ctx, epochFutureKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) ClearFutureEpoch(ctx context.Context) error {
	err := s.ms.Remove(ctx, epochFutureKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetConsensusParameters(ctx context.Context, params *beacon.ConsensusParameters) error {
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

// NewMutableState creates a new mutable beacon state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
