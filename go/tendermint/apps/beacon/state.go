package beacon

import (
	"fmt"

	"github.com/tendermint/iavl"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const stateBeacon = "beacon/beacon"

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

// GetBeacon gets the beacon for the node.
func (s *immutableState) GetBeacon() ([]byte, error) {
	_, b := s.Snapshot.Get([]byte(stateBeacon))
	if b == nil {
		return nil, beacon.ErrBeaconNotAvailable
	}

	return b, nil
}

// MutableState is a mutable beacon state wrapper.
type MutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *MutableState) setBeacon(newBeacon []byte) error {
	if l := len(newBeacon); l != beacon.BeaconSize {
		return fmt.Errorf("tendermint/beacon: unexpected beacon size: %d", l)
	}

	s.tree.Set(
		[]byte(stateBeacon),
		newBeacon,
	)

	return nil
}

// NewMutableState creates a new mutable beacon state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
