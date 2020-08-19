package state

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

var (
	// pvssStateKeyFmt is the current PVSS round key format.
	pvssStateKeyFmt = keyformat.New(0x44)
	// pvssPendingMockEpochKeyFmt is the pending mock epoch key format.
	pvssPendingMockEpochKeyFmt = keyformat.New(0x45)
)

func (s *ImmutableState) PVSSState(ctx context.Context) (*beacon.PVSSState, error) {
	data, err := s.is.Get(ctx, pvssStateKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var state beacon.PVSSState
	if err = cbor.Unmarshal(data, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &state, nil
}

func (s *MutableState) SetPVSSState(ctx context.Context, state *beacon.PVSSState) error {
	err := s.ms.Insert(ctx, pvssStateKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) ClearPVSSState(ctx context.Context) error {
	err := s.ms.Remove(ctx, pvssStateKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}

func (s *ImmutableState) PVSSPendingMockEpoch(ctx context.Context) (*beacon.EpochTime, error) {
	data, err := s.is.Get(ctx, pvssPendingMockEpochKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var pendingEpoch beacon.EpochTime
	if err = cbor.Unmarshal(data, &pendingEpoch); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &pendingEpoch, nil
}

func (s *MutableState) SetPVSSPendingMockEpoch(ctx context.Context, epoch beacon.EpochTime) error {
	err := s.ms.Insert(ctx, pvssPendingMockEpochKeyFmt.Encode(), cbor.Marshal(epoch))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) ClearPVSSPendingMockEpoch(ctx context.Context) error {
	err := s.ms.Remove(ctx, pvssPendingMockEpochKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}
