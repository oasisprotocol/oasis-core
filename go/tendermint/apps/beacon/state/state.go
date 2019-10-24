package state

import (
	"fmt"

	"github.com/tendermint/iavl"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

var (
	// beaconKeyFmt is the random beacon key format.
	//
	// Value is raw random beacon.
	beaconKeyFmt = keyformat.New(0x40)
)

type ImmutableState struct {
	*abci.ImmutableState
}

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

// Beacon gets the current random beacon value.
func (s *ImmutableState) Beacon() ([]byte, error) {
	_, b := s.Snapshot.Get(beaconKeyFmt.Encode())
	if b == nil {
		return nil, beacon.ErrBeaconNotAvailable
	}

	return b, nil
}

// MutableState is a mutable beacon state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (s *MutableState) SetBeacon(newBeacon []byte) error {
	if l := len(newBeacon); l != beacon.BeaconSize {
		return fmt.Errorf("tendermint/beacon: unexpected beacon size: %d", l)
	}

	s.tree.Set(beaconKeyFmt.Encode(), newBeacon)

	return nil
}

// NewMutableState creates a new mutable beacon state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
