package state

import (
	"context"
	"errors"
	"fmt"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs"
)

var (
	// beaconKeyFmt is the random beacon key format.
	//
	// Value is raw random beacon.
	beaconKeyFmt = keyformat.New(0x40)
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized beacon.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x41)
)

// ImmutableState is the immutable beacon state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationState, version int64) (*ImmutableState, error) {
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
