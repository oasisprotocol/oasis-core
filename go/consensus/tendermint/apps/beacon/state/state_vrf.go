package state

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

// vrfStateKeyFmt is the current VRF state key format.
var vrfStateKeyFmt = keyformat.New(0x46)

func (s *ImmutableState) VRFState(ctx context.Context) (*beacon.VRFState, error) {
	data, err := s.is.Get(ctx, vrfStateKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if data == nil {
		return nil, nil
	}

	var state beacon.VRFState
	if err = cbor.Unmarshal(data, &state); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if state.Pi == nil {
		state.Pi = make(map[signature.PublicKey]*signature.Proof)
	}
	return &state, nil
}

func (s *MutableState) SetVRFState(ctx context.Context, state *beacon.VRFState) error {
	err := s.ms.Insert(ctx, vrfStateKeyFmt.Encode(), cbor.Marshal(state))
	return abciAPI.UnavailableStateError(err)
}
