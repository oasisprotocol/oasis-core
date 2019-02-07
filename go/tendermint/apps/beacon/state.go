package beacon

import (
	"fmt"

	"github.com/tendermint/iavl"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const stateBeaconsMap = "beacon/beacons/%d"

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
func (s *immutableState) GetBeacon(epoch epochtime.EpochTime) ([]byte, error) {
	_, b := s.Snapshot.Get([]byte(fmt.Sprintf(stateBeaconsMap, epoch)))
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

func (s *MutableState) setBeacon(event *beacon.GenerateEvent) error {
	if l := len(event.Beacon); l != beacon.BeaconSize {
		return fmt.Errorf("tendermint/beacon: unexpected beacon size: %d", l)
	}

	// Keep a few beacons around.
	if event.Epoch > 2 {
		s.tree.Remove([]byte(fmt.Sprintf(stateBeaconsMap, event.Epoch-2)))
	}

	s.tree.Set(
		[]byte(fmt.Sprintf(stateBeaconsMap, event.Epoch)),
		event.Beacon,
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
